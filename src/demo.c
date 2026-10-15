#define _XOPEN_SOURCE 700
#include "demo.h"
#include "analyzer.h"
#include "baseline.h"
#include "scan.h"
#include "util.h"
#include <errno.h>
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

/* ---- a tiny model of a Linux module environment, written to disk -------- */

typedef struct {
    char name[48];
    unsigned long size, ref;
    char deps[48];
    char src[32];
    char taint[8];
    char path[96];     /* modules.dep entry, "" = none */
    int in_proc, in_sys;
} dm_t;

typedef struct {
    dm_t m[24];
    int n;
} model_t;

static void model_add(model_t *md, const char *name, unsigned long size, unsigned long ref,
                      const char *deps, const char *src, const char *taint, const char *path)
{
    dm_t *d = &md->m[md->n++];
    memset(d, 0, sizeof(*d));
    util_copy(d->name, sizeof(d->name), name);
    d->size = size;
    d->ref = ref;
    util_copy(d->deps, sizeof(d->deps), deps);
    util_copy(d->src, sizeof(d->src), src);
    util_copy(d->taint, sizeof(d->taint), taint);
    util_copy(d->path, sizeof(d->path), path);
    d->in_proc = d->in_sys = 1;
}

static dm_t *model_find(model_t *md, const char *name)
{
    for (int i = 0; i < md->n; i++)
        if (strcmp(md->m[i].name, name) == 0)
            return &md->m[i];
    return NULL;
}

static void model_base(model_t *md)
{
    md->n = 0;
    model_add(md, "ext4", 729088, 1, "mbcache,jbd2,", "A1B2C3D4E5F6A7B8C9D0E1F", "", "kernel/fs/ext4/ext4.ko.xz");
    model_add(md, "jbd2", 163840, 1, "ext4,", "B2C3D4E5F6A7B8C9D0E1F2A", "", "kernel/fs/jbd2/jbd2.ko.xz");
    model_add(md, "mbcache", 16384, 1, "ext4,", "C3D4E5F6A7B8C9D0E1F2A3B", "", "kernel/fs/mbcache.ko.xz");
    model_add(md, "nf_tables", 286720, 91, "nft_chain_nat,", "D4E5F6A7B8C9D0E1F2A3B4C", "", "kernel/net/netfilter/nf_tables.ko.xz");
    model_add(md, "nfnetlink", 20480, 2, "nf_tables,", "E5F6A7B8C9D0E1F2A3B4C5D", "", "kernel/net/netfilter/nfnetlink.ko.xz");
    model_add(md, "e1000", 155648, 0, "-", "F6A7B8C9D0E1F2A3B4C5D6E", "", "kernel/drivers/net/ethernet/intel/e1000/e1000.ko.xz");
    model_add(md, "snd_hda_intel", 57344, 3, "snd_hda_codec,", "A7B8C9D0E1F2A3B4C5D6E7F", "", "kernel/sound/pci/hda/snd-hda-intel.ko.xz");
    model_add(md, "usbhid", 65536, 0, "-", "B8C9D0E1F2A3B4C5D6E7F8A", "", "kernel/drivers/hid/usbhid/usbhid.ko.xz");
    model_add(md, "br_netfilter", 32768, 0, "-", "D0E1F2A3B4C5D6E7F8A9B0C", "", "kernel/net/bridge/br_netfilter.ko.xz");
}

/* ---- the scenarios -------------------------------------------------------- */

static void s_clean(model_t *md) { (void)md; }

static void s_modprobe(model_t *md)
{
    model_add(md, "dummy", 16384, 0, "-", "FFFFFFFFFFFFFFFFFFFFFFF", "", "kernel/drivers/net/dummy.ko.xz");
}

static void s_insmod(model_t *md)
{
    model_add(md, "evilmod", 20480, 0, "-", "0123456789ABCDEF0123456", "", "");
}

static void s_hide_proc(model_t *md)
{
    model_add(md, "stealth", 12288, 0, "-", "AAAAAAAAAAAAAAAAAAAAAAA", "", "");
    md->m[md->n - 1].in_proc = 0;
}

static void s_hide_sys(model_t *md)
{
    model_find(md, "usbhid")->in_sys = 0;
}

static void s_replaced(model_t *md)
{
    dm_t *d = model_find(md, "e1000");
    util_copy(d->src, sizeof(d->src), "DEADBEEFDEADBEEFDEADBEE");
    d->size = 200000;
}

static void s_rootkit(model_t *md)
{
    model_add(md, "diamorphine", 16384, 0, "-", "", "OE", "");
}

static void s_unloaded(model_t *md)
{
    for (int i = 0; i < md->n; i++)
        if (strcmp(md->m[i].name, "br_netfilter") == 0) {
            md->m[i] = md->m[--md->n];
            return;
        }
}

typedef struct {
    const char *name;                 /* what happened */
    void (*mutate)(model_t *);
    risk_level_t expect;              /* expected verdict */
    const char *rule;                 /* rule that must be among the findings */
    int tamper;                       /* corrupt the baseline file instead */
} scenario_t;

static const scenario_t k_scenarios[] = {
    {"Clean system, nothing changed", s_clean, RISK_NONE, NULL, 0},
    {"New driver installed the normal way", s_modprobe, RISK_MEDIUM, "NOT_IN_BASELINE", 0},
    {"Unknown module loaded with insmod", s_insmod, RISK_HIGH, "NO_MODULE_FILE", 0},
    {"Module hides itself from /proc/modules", s_hide_proc, RISK_CRITICAL, "HIDDEN_FROM_PROC", 0},
    {"Module hides itself from /sys/module", s_hide_sys, RISK_HIGH, "HIDDEN_FROM_SYSFS", 0},
    {"Driver binary replaced (new build hash)", s_replaced, RISK_HIGH, "SRCVERSION_CHANGED", 0},
    {"Known rootkit name, unsigned module", s_rootkit, RISK_CRITICAL, "SUSPICIOUS_NAME", 0},
    {"Module disappeared since the baseline", s_unloaded, RISK_LOW, "MISSING", 0},
    {"Baseline file edited by an attacker", s_clean, RISK_NONE, NULL, 1},
};
#define N_SCENARIOS ((int)(sizeof(k_scenarios) / sizeof(k_scenarios[0])))

/* ---- sandbox on disk ------------------------------------------------------- */

typedef struct {
    char proc[320], sys[320], dep[320];
} paths_t;

static int put(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    return fclose(f);
}

static int write_model(const model_t *md, const char *dir, paths_t *p)
{
    char b[700], t[760];
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return -1;
    snprintf(p->proc, sizeof(p->proc), "%s/proc_modules", dir);
    snprintf(p->sys, sizeof(p->sys), "%s/sys", dir);
    snprintf(p->dep, sizeof(p->dep), "%s/modules.dep", dir);
    if (mkdir(p->sys, 0700) != 0 && errno != EEXIST)
        return -1;

    FILE *fp = fopen(p->proc, "w"), *fd = fopen(p->dep, "w");
    if (!fp || !fd) {
        if (fp)
            fclose(fp);
        if (fd)
            fclose(fd);
        return -1;
    }
    for (int i = 0; i < md->n; i++) {
        const dm_t *d = &md->m[i];
        if (d->in_proc) {
            fprintf(fp, "%s %lu %lu %s Live 0xffffffffc0000000%s%s%s\n", d->name, d->size, d->ref,
                    d->deps, d->taint[0] ? " (" : "", d->taint, d->taint[0] ? ")" : "");
        }
        if (d->path[0])
            fprintf(fd, "%s:\n", d->path);
        if (d->in_sys) {
            snprintf(b, sizeof(b), "%s/%s", p->sys, d->name);
            mkdir(b, 0700);
            snprintf(t, sizeof(t), "%s/holders", b);
            mkdir(t, 0700);
            snprintf(t, sizeof(t), "%s/initstate", b);
            put(t, "live\n");
            snprintf(t, sizeof(t), "%s/taint", b);
            put(t, d->taint);
            snprintf(t, sizeof(t), "%s/srcversion", b);
            put(t, d->src);
            snprintf(t, sizeof(t), "%s/version", b);
            put(t, "1.0\n");
            snprintf(t, sizeof(t), "%s/coresize", b);
            snprintf(b, sizeof(b), "%lu\n", d->size > 512 ? d->size - 512 : 0);
            put(t, b);
            snprintf(b, sizeof(b), "%s/%s/initsize", p->sys, d->name);
            put(b, "512\n");
        }
    }
    int bad = fclose(fp) != 0;
    bad |= fclose(fd) != 0;
    return bad ? -1 : 0;
}

static int rm_cb(const char *path, const struct stat *sb, int type, struct FTW *ftw)
{
    (void)sb;
    (void)type;
    (void)ftw;
    return remove(path);
}

/* Remove the temporary tree. Only ever called on a directory this program
   created with mkdtemp(), and refuses anything that does not look like it. */
static void remove_tree(const char *root)
{
    if (!root || !strstr(root, "kmrd-demo-") || strlen(root) < 16)
        return;
    nftw(root, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

/* ---- running and printing -------------------------------------------------- */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

typedef struct {
    int refused;                 /* baseline rejected */
    risk_level_t level;
    int score;
    char why[120];
    int ok;                      /* matches the expectation */
    double ms;
    int modules;
} outcome_t;

static void summarise(const analysis_t *an, const char *rule, outcome_t *o)
{
    o->level = an->flagged ? an->max_level : RISK_NONE;
    o->score = an->flagged ? an->max_score : 0;
    if (!an->flagged) {
        util_copy(o->why, sizeof(o->why), "nothing flagged");
        return;
    }
    const module_result_t *r = &an->items[0];
    char rules[96] = "";
    size_t off = 0;
    for (int k = 0; k < r->nfindings && k < 2; k++) {
        int w = snprintf(rules + off, sizeof(rules) - off, "%s%s", k ? " + " : "",
                         r->findings[k].rule);
        if (w < 0 || (size_t)w >= sizeof(rules) - off)
            break;
        off += (size_t)w;
    }
    if (r->nfindings > 2 && off + 16 < sizeof(rules))
        snprintf(rules + off, sizeof(rules) - off, " +%d more", r->nfindings - 2);
    snprintf(o->why, sizeof(o->why), "%s: %s", r->name, rules);
    (void)rule;
}

static int has_rule(const analysis_t *an, const char *rule)
{
    for (int i = 0; i < an->count; i++)
        for (int k = 0; k < an->items[i].nfindings; k++)
            if (strcmp(an->items[i].findings[k].rule, rule) == 0)
                return 1;
    return 0;
}

static void run_scenario(const scenario_t *sc, const model_t *base, const char *root, int idx,
                         const char *base_path, outcome_t *o)
{
    memset(o, 0, sizeof(*o));
    double t0 = now_ms();
    char dir[340], err[200], bpath[400];
    snprintf(dir, sizeof(dir), "%s/s%d", root, idx);

    model_t md = *base;
    sc->mutate(&md);
    paths_t p;
    if (write_model(&md, dir, &p) != 0) {
        util_copy(o->why, sizeof(o->why), "could not build the fake system");
        return;
    }

    util_copy(bpath, sizeof(bpath), base_path);
    if (sc->tamper) {
        /* an attacker edits one number in the saved baseline */
        snprintf(bpath, sizeof(bpath), "%s/tampered.baseline", dir);
        FILE *in = fopen(base_path, "rb"), *out = fopen(bpath, "wb");
        if (in && out) {
            char buf[4096];
            size_t n, total = 0;
            int done = 0;
            while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
                for (size_t i = 0; i < n && !done; i++)
                    if (total + i > 60 && buf[i] >= '1' && buf[i] <= '8') {
                        buf[i]++;
                        done = 1;
                    }
                total += n;
                fwrite(buf, 1, n, out);
            }
        }
        if (in)
            fclose(in);
        if (out)
            fclose(out);
    }

    scan_config_t cfg = {p.proc, p.sys, p.dep, "6.1.0-demo"};
    scan_result_t scan;
    if (scan_run(&cfg, &scan, err, sizeof(err)) != 0) {
        util_copy(o->why, sizeof(o->why), err);
        return;
    }
    o->modules = scan.records.count;

    baseline_t b;
    if (baseline_load(bpath, &b, err, sizeof(err)) != 0) {
        o->refused = 1;
        util_copy(o->why, sizeof(o->why), "baseline failed its checksum - detector refuses to trust it");
        o->ok = sc->tamper;
        scan_free(&scan);
        o->ms = now_ms() - t0;
        return;
    }
    analysis_t an;
    if (analyzer_run(&scan, &b, &an) == 0) {
        summarise(&an, sc->rule, o);
        o->ok = !sc->tamper && o->level == sc->expect && (!sc->rule || has_rule(&an, sc->rule));
        analyzer_free(&an);
    }
    baseline_free(&b);
    scan_free(&scan);
    o->ms = now_ms() - t0;
}

#define NAME_W 42

static void print_row(FILE *out, const ui_t *ui, int pass_mark, const char *name,
                      const outcome_t *o, const char *sym_override)
{
    const char *R = ui_style(ui, UI_RESET);
    const char *mark = sym_override ? sym_override : ui_sym(ui, pass_mark ? UI_SYM_OK : UI_SYM_FAIL);
    const char *mc = sym_override ? ui_style(ui, UI_GREY) : ui_style(ui, pass_mark ? UI_GREEN : UI_RED);
    const char *verdict = o->refused ? "REFUSED" : (o->level == RISK_NONE ? "CLEAN" : risk_level_name(o->level));
    const char *vstyle = o->refused ? ui_level_style(ui, RISK_HIGH) : ui_level_style(ui, o->level);
    char dots[NAME_W + 1];
    int nl = (int)strlen(name);
    int nd = NAME_W - nl;
    if (nd < 1)
        nd = 1;
    for (int i = 0; i < nd && i < NAME_W; i++)
        dots[i] = '.';
    dots[nd < NAME_W ? nd : NAME_W] = '\0';
    fprintf(out, "  %s%s%s %s %s%s%s %s %-8s %s %3d  %s%s%s\n", mc, mark, R, name,
            ui_style(ui, UI_GREY), dots, R, vstyle, verdict, R, o->score, ui_style(ui, UI_DIM),
            o->why, R);
}

int demo_run(FILE *out, const ui_t *ui)
{
    const char *tmp = getenv("TMPDIR");
    char root[300];
    snprintf(root, sizeof(root), "%s/kmrd-demo-XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (!mkdtemp(root)) {
        fprintf(stderr, "error: cannot create a temporary directory: %s\n", strerror(errno));
        return 2;
    }

    /* the trusted baseline, taken from the clean fake system */
    model_t base;
    model_base(&base);
    paths_t p0;
    char dir0[320], berr[200], base_path[320];
    snprintf(dir0, sizeof(dir0), "%s/base", root);
    snprintf(base_path, sizeof(base_path), "%s/trusted.baseline", root);
    scan_config_t cfg0;
    scan_result_t s0;
    if (write_model(&base, dir0, &p0) != 0) {
        remove_tree(root);
        return 2;
    }
    cfg0 = (scan_config_t){p0.proc, p0.sys, p0.dep, "6.1.0-demo"};
    if (scan_run(&cfg0, &s0, berr, sizeof(berr)) != 0 ||
        baseline_save(base_path, &s0, berr, sizeof(berr)) != 0) {
        fprintf(stderr, "error: %s\n", berr);
        remove_tree(root);
        return 2;
    }
    int base_modules = s0.records.count;
    scan_free(&s0);

    char l1[160], l2[160];
    snprintf(l1, sizeof(l1), "KMRD %s Kernel Module Rootkit Detector", ui->unicode ? "\xc2\xb7" : "-");
    snprintf(l2, sizeof(l2), "%d scans on fake systems, then this machine", N_SCENARIOS);
    const char *lines[] = {l1, l2, "Nothing is loaded into the kernel. Real detector, fake systems."};
    fputc('\n', out);
    ui_box(ui, out, lines, 3, 62);
    fprintf(out, "\n  Trusted baseline: %d modules.  Each scan below changes the system, then asks\n"
                 "  the detector for a verdict.\n\n", base_modules);
    fprintf(out, "  %s    %-*s %-8s %s  %s%s\n", ui_style(ui, UI_GREY), NAME_W + 1, "WHAT HAPPENED",
            "VERDICT", "SCORE", "WHY", ui_style(ui, UI_RESET));

    int pass = 0;
    double total = 0;
    for (int i = 0; i < N_SCENARIOS; i++) {
        outcome_t o;
        run_scenario(&k_scenarios[i], &base, root, i, base_path, &o);
        print_row(out, ui, o.ok, k_scenarios[i].name, &o, NULL);
        pass += o.ok;
        total += o.ms;
    }

    fputc('\n', out);
    if (pass == N_SCENARIOS)
        fprintf(out, "  %s%s %d/%d scans gave the expected verdict%s   %s(%.1f ms in total)%s\n",
                ui_style(ui, UI_GREEN), ui_sym(ui, UI_SYM_OK), pass, N_SCENARIOS,
                ui_style(ui, UI_RESET), ui_style(ui, UI_GREY), total, ui_style(ui, UI_RESET));
    else
        fprintf(out, "  %s%s only %d/%d scans gave the expected verdict%s\n",
                ui_style(ui, UI_RED), ui_sym(ui, UI_SYM_FAIL), pass, N_SCENARIOS,
                ui_style(ui, UI_RESET));

    /* the real machine */
    fprintf(out, "\n  %sThis machine%s\n", ui_style(ui, UI_BOLD), ui_style(ui, UI_RESET));
    struct utsname un;
    char kernel[65] = "unknown", dep[300], lerr[200], lbase[320];
    if (uname(&un) == 0)
        snprintf(kernel, sizeof(kernel), "%s", un.release);
    snprintf(dep, sizeof(dep), "/lib/modules/%s/modules.dep", kernel);
    snprintf(lbase, sizeof(lbase), "%s/live.baseline", root);
    scan_config_t lc = {"/proc/modules", "/sys/module", dep, kernel};
    scan_result_t l1s, l2s;
    outcome_t lo;
    memset(&lo, 0, sizeof(lo));
    if (scan_run(&lc, &l1s, lerr, sizeof(lerr)) != 0) {
        fprintf(out, "  %s no /proc/modules here (not Linux?): live scan skipped\n",
                ui_sym(ui, UI_SYM_WARN));
    } else {
        int mods = 0;
        for (int i = 0; i < l1s.records.count; i++)
            mods += l1s.records.items[i].in_proc;
        baseline_t lb;
        analysis_t lan;
        double t0 = now_ms();
        if (baseline_save(lbase, &l1s, lerr, sizeof(lerr)) == 0 &&
            scan_run(&lc, &l2s, lerr, sizeof(lerr)) == 0) {
            if (baseline_load(lbase, &lb, lerr, sizeof(lerr)) == 0 &&
                analyzer_run(&l2s, &lb, &lan) == 0) {
                summarise(&lan, NULL, &lo);
                analyzer_free(&lan);
                baseline_free(&lb);
            }
            scan_free(&l2s);
        }
        lo.ms = now_ms() - t0;
        char nm[96];
        snprintf(nm, sizeof(nm), "Live kernel %s, %d modules", kernel, mods);
        print_row(out, ui, 1, nm, &lo, ui_sym(ui, UI_SYM_DOT));
        scan_free(&l1s);
    }

    fprintf(out, "\n  %sTry it for real:%s\n"
                 "    sudo ./detector create-baseline      %s# remember what is loaded now%s\n"
                 "    sudo ./detector scan --explain       %s# scan with proof under each finding%s\n"
                 "    sudo ./detector monitor              %s# watch live, alert on changes%s\n\n",
            ui_style(ui, UI_BOLD), ui_style(ui, UI_RESET), ui_style(ui, UI_GREY),
            ui_style(ui, UI_RESET), ui_style(ui, UI_GREY), ui_style(ui, UI_RESET),
            ui_style(ui, UI_GREY), ui_style(ui, UI_RESET));

    remove_tree(root);
    return pass == N_SCENARIOS ? 0 : 1;
}
