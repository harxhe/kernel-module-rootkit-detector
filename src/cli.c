/* Kernel Module Rootkit Detector - command line front end for phases 5-7.
 *
 * src/main.c is the original phase-2 command skeleton and is left untouched;
 * this file is the integrated CLI (build target "detector"), main.c is built
 * separately as "legacy" (see GNUmakefile).
 *
 *   detector <command> [options]        (the "--command" spelling also works)
 *
 * Exit codes: 0 = nothing at/above --fail-on level (or command succeeded),
 *             1 = findings at/above --fail-on level (or differences found),
 *             2 = usage or runtime error.                                  */

#include "analyzer.h"
#include "baseline.h"
#include "demo.h"
#include "monitor.h"
#include "progress.h"
#include "report.h"
#include "scan.h"
#include "ui.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>

#define VERSION "1.0.0"

typedef struct {
    const char *proc_path;
    const char *sys_root;
    const char *moddep_path;   /* NULL = derive from kernel release */
    const char *kernel;        /* NULL = uname -r */
    const char *baseline_path;
    const char *output;
    const char *log;
    int json;
    int force;
    int quiet;
    int explain;
    double interval_s;
    int count;
    ui_mode_t ui_mode;
    risk_level_t fail_on;
} options_t;

typedef int (*cmd_fn)(const options_t *);

static int cmd_list(const options_t *o);
static int cmd_scan(const options_t *o);
static int cmd_create_baseline(const options_t *o);
static int cmd_compare(const options_t *o);
static int cmd_report(const options_t *o);
static int cmd_monitor(const options_t *o);
static int cmd_demo(const options_t *o);

static const struct {
    const char *name;
    cmd_fn fn;
    const char *description;
} g_commands[] = {
    {"list", cmd_list, "List all loaded kernel modules with metadata"},
    {"scan", cmd_scan, "Scan, compare with baseline, score risk, print findings"},
    {"create-baseline", cmd_create_baseline, "Record the current modules as the trusted baseline"},
    {"compare", cmd_compare, "Show modules added/removed/changed since the baseline"},
    {"report", cmd_report, "Full detection report (all modules, optional file/log)"},
    {"demo", cmd_demo, "Quick self-demonstration: 9 scans on fake systems, then this machine"},
    {"monitor", cmd_monitor, "Keep watching: re-scan every few seconds and alert on changes"},
    {NULL, NULL, NULL},
};

static void usage(FILE *out, const char *prog)
{
    fprintf(out, "Kernel Module Rootkit Detector %s\n\n", VERSION);
    fprintf(out, "Usage: %s <command> [options]\n\nCommands:\n", prog);
    for (int i = 0; g_commands[i].name; i++)
        fprintf(out, "  %-16s %s\n", g_commands[i].name, g_commands[i].description);
    fprintf(out, "\nOptions:\n"
                 "  --baseline FILE     baseline file (default %s)\n"
                 "  --json              machine readable output (scan, report)\n"
                 "  --output FILE       also write the report to FILE\n"
                 "  --log FILE          append a history entry to FILE\n"
                 "  --fail-on LEVEL     exit 1 when a module reaches low|medium|high|critical\n"
                 "                      (default high)\n"
                 "  --force             create-baseline even if the system looks compromised\n"
                 "  --quiet             do not print the report to stdout\n"
                 "  --interval SECONDS  monitor: pause between scans (default 2)\n"
                 "  --count N           monitor: stop after N scans (default: until Ctrl+C)\n"
                 "  --explain           show the raw evidence under each finding (scan, report)\n"
                 "  --ui MODE           auto|plain|fancy: colour and boxes on a terminal\n"
                 "                      (default auto; files, pipes and --json stay plain)\n"
                 "  --proc FILE         /proc/modules path        (testing)\n"
                 "  --sys DIR           /sys/module path          (testing)\n"
                 "  --moddep FILE       modules.dep path          (testing)\n"
                 "  --kernel RELEASE    kernel release override   (testing)\n"
                 "  -h, --help          this help\n"
                 "  --version           print version\n"
                 "\nExit codes: 0 ok/clean, 1 findings (or differences), 2 error.\n",
            BASELINE_DEFAULT_PATH);
}

/* ------------------------------------------------------------------ */

static void make_scan_config(const options_t *o, scan_config_t *cfg, char *moddep,
                             size_t moddep_sz)
{
    cfg->proc_path = o->proc_path;
    cfg->sys_root = o->sys_root;
    cfg->kernel_release = o->kernel;
    if (o->moddep_path) {
        cfg->moddep_path = o->moddep_path;
    } else {
        snprintf(moddep, moddep_sz, "/lib/modules/%s/modules.dep", o->kernel);
        cfg->moddep_path = moddep;
    }
}

static int run_scan(const options_t *o, scan_result_t *scan)
{
    char moddep[600];
    scan_config_t cfg;
    make_scan_config(o, &cfg, moddep, sizeof(moddep));

    char err[256];
    if (scan_run(&cfg, scan, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: scan failed: %s\n", err);
        return -1;
    }
    return 0;
}

/* Load the baseline if it exists. Returns:
     1 loaded, 0 not present (note set), -1 present but invalid (error printed) */
static int load_baseline(const options_t *o, baseline_t *b, const char **note)
{
    static char note_buf[300];
    struct stat st;
    *note = NULL;
    if (stat(o->baseline_path, &st) != 0) {
        snprintf(note_buf, sizeof(note_buf),
                 "no baseline file at %s (run create-baseline)", o->baseline_path);
        *note = note_buf;
        return 0;
    }
    char err[256];
    if (baseline_load(o->baseline_path, b, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        fprintf(stderr, "       A damaged baseline cannot be trusted; refusing to continue.\n"
                        "       Recreate it with create-baseline on a known-good system.\n");
        return -1;
    }
    return 1;
}

static int emit_report(const options_t *o, const report_ctx_t *ctx)
{
    if (!o->quiet) {
        ui_t ui = ui_detect(o->ui_mode, stdout);
        if (o->json) {
            report_json(stdout, ctx);
        } else if (ui_fancy(&ui)) {
            report_ctx_t styled = *ctx;
            styled.ui = &ui;
            report_fancy(stdout, &styled);
        } else {
            report_text(stdout, ctx);
        }
    }
    if (o->output) {
        FILE *f = fopen(o->output, "w");
        if (!f) {
            fprintf(stderr, "error: cannot write %s: %s\n", o->output, strerror(errno));
            return -1;
        }
        if (o->json)
            report_json(f, ctx);
        else
            report_text(f, ctx);
        if (fclose(f) != 0) {
            fprintf(stderr, "error: write error on %s\n", o->output);
            return -1;
        }
        if (!o->quiet && !o->json)
            printf("Report saved to %s\n", o->output);
    }
    if (o->log && report_append_log(o->log, ctx) != 0) {
        fprintf(stderr, "error: cannot append to log %s: %s\n", o->log, strerror(errno));
        return -1;
    }
    return 0;
}

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int do_scan(const options_t *o, int full)
{
    scan_result_t scan;
    if (run_scan(o, &scan) != 0)
        return 2;

    baseline_t base;
    const char *note;
    double tb = now_ms();
    int have = load_baseline(o, &base, &note);
    double t_baseline = now_ms() - tb;
    if (have < 0) {
        scan_free(&scan);
        return 2;
    }

    analysis_t an;
    double ta = now_ms();
    if (analyzer_run(&scan, have ? &base : NULL, &an) != 0) {
        fprintf(stderr, "error: out of memory\n");
        if (have)
            baseline_free(&base);
        scan_free(&scan);
        return 2;
    }
    double t_analyze = now_ms() - ta;

    /* stage summary on stderr, only when styling is active for it */
    ui_t eui = ui_detect(o->ui_mode, stderr);
    if (ui_fancy(&eui) && !o->json && !o->quiet)
        progress_print(stderr, &eui, &scan, &an, t_baseline, t_analyze);

    report_ctx_t ctx = {&scan, &an, have ? &base : NULL, o->baseline_path, note, full, NULL,
                        o->explain, o->proc_path, o->sys_root};
    int rc = emit_report(o, &ctx) == 0 ? 0 : 2;
    if (rc == 0 && an.flagged && an.max_level >= o->fail_on)
        rc = 1;

    analyzer_free(&an);
    if (have)
        baseline_free(&base);
    scan_free(&scan);
    return rc;
}

static int cmd_scan(const options_t *o) { return do_scan(o, 0); }
static int cmd_report(const options_t *o) { return do_scan(o, 1); }

static int cmd_demo(const options_t *o)
{
    ui_t ui = ui_detect(o->ui_mode, stdout);
    return demo_run(stdout, &ui);
}

static int cmd_monitor(const options_t *o)
{
    char moddep[600];
    monitor_opts_t m;
    memset(&m, 0, sizeof(m));
    make_scan_config(o, &m.scan, moddep, sizeof(moddep));
    m.baseline_path = o->baseline_path;
    m.interval_ms = (int)(o->interval_s * 1000.0 + 0.5);
    m.max_scans = o->count;
    m.ui = ui_detect(o->ui_mode, stdout);
    m.json = o->json;
    m.explain = o->explain;
    m.fail_on = o->fail_on;
    m.log_path = o->log;
    return monitor_run(&m);
}

static int cmd_list(const options_t *o)
{
    scan_result_t scan;
    if (run_scan(o, &scan) != 0)
        return 2;

    printf("%-24s %10s %4s  %-8s %-18s %s\n", "Module", "Size", "Ref", "State",
           "Srcversion", "Origin");
    for (int i = 0; i < scan.records.count; i++) {
        const module_record_t *m = &scan.records.items[i];
        const char *state = m->in_proc ? (m->initstate[0] ? m->initstate : "?")
                                       : "HIDDEN";
        printf("%-24s %10lu %4lu  %-8s %-18.18s %s\n", m->base.name, m->base.size,
               m->base.ref_count, state, m->srcversion[0] ? m->srcversion : "-",
               m->in_moddep ? m->path : "(unknown)");
    }
    printf("\n%d module(s)", scan.records.count);
    if (scan.proc_skipped)
        printf(", %d malformed line(s) ignored", scan.proc_skipped);
    printf("\n");
    scan_free(&scan);
    return 0;
}

static int cmd_create_baseline(const options_t *o)
{
    scan_result_t scan;
    if (run_scan(o, &scan) != 0)
        return 2;

    /* Never bless a system that already shows rootkit indicators. */
    analysis_t an;
    if (analyzer_run(&scan, NULL, &an) != 0) {
        scan_free(&scan);
        return 2;
    }
    if (an.flagged && an.max_level >= RISK_HIGH && !o->force) {
        fprintf(stderr, "error: refusing to create a baseline: the system already shows "
                        "%s-risk indicators.\n", risk_level_name(an.max_level));
        for (int i = 0; i < an.count && an.items[i].score >= 50; i++)
            fprintf(stderr, "  %s: %s\n", an.items[i].name,
                    an.items[i].findings[0].reason);
        fprintf(stderr, "Investigate first, or use --force if you accept the risk.\n");
        analyzer_free(&an);
        scan_free(&scan);
        return 2;
    }
    analyzer_free(&an);

    char err[256];
    if (baseline_save(o->baseline_path, &scan, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\n", err);
        scan_free(&scan);
        return 2;
    }
    int n = 0;
    for (int i = 0; i < scan.records.count; i++)
        n += scan.records.items[i].in_proc;
    printf("Baseline created: %d modules (kernel %s) saved to %s\n", n, scan.kernel,
           o->baseline_path);
    scan_free(&scan);
    return 0;
}

static void describe_mask(int mask, char *buf, size_t sz)
{
    buf[0] = '\0';
    const struct { int bit; const char *s; } t[] = {
        {DIFF_SRCVER, "srcversion"}, {DIFF_SIZE, "size"},
        {DIFF_DEPS, "deps"},         {DIFF_VERSION, "version"}};
    for (unsigned i = 0; i < sizeof(t) / sizeof(t[0]); i++)
        if (mask & t[i].bit) {
            if (buf[0])
                strncat(buf, ",", sz - strlen(buf) - 1);
            strncat(buf, t[i].s, sz - strlen(buf) - 1);
        }
}

static int cmd_compare(const options_t *o)
{
    scan_result_t scan;
    if (run_scan(o, &scan) != 0)
        return 2;

    baseline_t base;
    char err[256];
    if (baseline_load(o->baseline_path, &base, err, sizeof(err)) != 0) {
        fprintf(stderr, "error: %s\nRun `detector create-baseline` first.\n", err);
        scan_free(&scan);
        return 2;
    }
    baseline_diff_t d;
    if (baseline_diff(&base, &scan, &d) != 0) {
        fprintf(stderr, "error: out of memory\n");
        baseline_free(&base);
        scan_free(&scan);
        return 2;
    }

    int cur = 0;
    for (int i = 0; i < scan.records.count; i++)
        cur += scan.records.items[i].in_proc;

    printf("=== Baseline Comparison ===\n");
    printf("Baseline modules: %d (kernel %s)\n", base.count,
           base.kernel[0] ? base.kernel : "?");
    printf("Current modules : %d (kernel %s)\n", cur, scan.kernel);
    if (base.kernel[0] && strcmp(base.kernel, scan.kernel) != 0)
        printf("Note: kernel release differs; size/srcversion changes are expected.\n");

    printf("\nAdded since baseline (%d):\n", d.n_added);
    for (int i = 0; i < d.n_added; i++) {
        const module_record_t *m = &scan.records.items[d.added[i]];
        printf("  [ADDED]   %-24s size=%lu\n", m->base.name, m->base.size);
    }
    printf("\nRemoved since baseline (%d):\n", d.n_removed);
    for (int i = 0; i < d.n_removed; i++)
        printf("  [REMOVED] %s\n", base.items[d.removed[i]].name);
    printf("\nChanged since baseline (%d):\n", d.n_changed);
    for (int i = 0; i < d.n_changed; i++) {
        char what[64];
        describe_mask(d.changed_mask[i], what, sizeof(what));
        printf("  [CHANGED] %-24s (%s)\n", scan.records.items[d.changed[i]].base.name, what);
    }

    int diffs = d.n_added + d.n_removed + d.n_changed;
    printf("\n%s\n", diffs ? "Differences found." : "No differences from baseline.");

    baseline_diff_free(&d);
    baseline_free(&base);
    scan_free(&scan);
    return diffs ? 1 : 0;
}

/* ------------------------------------------------------------------ */

static int find_command(const char *s)
{
    if (s[0] == '-' && s[1] == '-')
        s += 2;
    for (int i = 0; g_commands[i].name; i++)
        if (strcmp(s, g_commands[i].name) == 0)
            return i;
    return -1;
}

/* Fetch the value of "--opt VALUE" or "--opt=VALUE". */
static const char *opt_value(int argc, char **argv, int *i, const char *name)
{
    size_t n = strlen(name);
    const char *a = argv[*i];
    if (strncmp(a, name, n) != 0)
        return NULL;
    if (a[n] == '=')
        return a + n + 1;
    if (a[n] != '\0')
        return NULL;
    if (*i + 1 >= argc) {
        fprintf(stderr, "error: option %s needs a value\n", name);
        exit(2);
    }
    return argv[++*i];
}

int main(int argc, char **argv)
{
    struct utsname un;
    char release[65] = "unknown";
    if (uname(&un) == 0)
        snprintf(release, sizeof(release), "%s", un.release);

    options_t o = {
        .proc_path = "/proc/modules",
        .sys_root = "/sys/module",
        .moddep_path = NULL,
        .kernel = release,
        .baseline_path = BASELINE_DEFAULT_PATH,
        .fail_on = RISK_HIGH,
        .interval_s = 2.0,
    };

    int cmd = -1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v;
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout, argv[0]);
            return 0;
        }
        if (strcmp(a, "--version") == 0) {
            printf("detector %s\n", VERSION);
            return 0;
        }
        if (strcmp(a, "--json") == 0) { o.json = 1; continue; }
        if (strcmp(a, "--force") == 0) { o.force = 1; continue; }
        if (strcmp(a, "--quiet") == 0) { o.quiet = 1; continue; }
        if (strcmp(a, "--explain") == 0) { o.explain = 1; continue; }
        if ((v = opt_value(argc, argv, &i, "--baseline"))) { o.baseline_path = v; continue; }
        if ((v = opt_value(argc, argv, &i, "--output")))   { o.output = v; continue; }
        if ((v = opt_value(argc, argv, &i, "--log")))      { o.log = v; continue; }
        if ((v = opt_value(argc, argv, &i, "--proc")))     { o.proc_path = v; continue; }
        if ((v = opt_value(argc, argv, &i, "--sys")))      { o.sys_root = v; continue; }
        if ((v = opt_value(argc, argv, &i, "--moddep")))   { o.moddep_path = v; continue; }
        if ((v = opt_value(argc, argv, &i, "--kernel")))   { o.kernel = v; continue; }
        if ((v = opt_value(argc, argv, &i, "--interval"))) {
            char *end;
            o.interval_s = strtod(v, &end);
            if (end == v || *end || o.interval_s < 0 || o.interval_s > 3600) {
                fprintf(stderr, "error: --interval expects seconds between 0 and 3600\n");
                return 2;
            }
            continue;
        }
        if ((v = opt_value(argc, argv, &i, "--count"))) {
            char *end;
            long n = strtol(v, &end, 10);
            if (end == v || *end || n < 0 || n > 1000000) {
                fprintf(stderr, "error: --count expects a non-negative number\n");
                return 2;
            }
            o.count = (int)n;
            continue;
        }
        if ((v = opt_value(argc, argv, &i, "--ui"))) {
            if (ui_mode_parse(v, &o.ui_mode) != 0) {
                fprintf(stderr, "error: --ui expects auto|plain|fancy\n");
                return 2;
            }
            continue;
        }
        if ((v = opt_value(argc, argv, &i, "--fail-on"))) {
            if (risk_level_parse(v, &o.fail_on) != 0) {
                fprintf(stderr, "error: --fail-on expects low|medium|high|critical\n");
                return 2;
            }
            continue;
        }

        int c = find_command(a);
        if (c >= 0) {
            if (cmd >= 0 && cmd != c) {
                fprintf(stderr, "error: more than one command given\n");
                return 2;
            }
            cmd = c;
            continue;
        }
        fprintf(stderr, "error: unknown argument: %s\n\n", a);
        usage(stderr, argv[0]);
        return 2;
    }

    if (cmd < 0) {
        usage(stderr, argv[0]);
        return 2;
    }
    return g_commands[cmd].fn(&o);
}
