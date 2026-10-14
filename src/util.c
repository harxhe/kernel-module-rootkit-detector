#include "util.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

int util_valid_module_name(const char *s)
{
    if (!s || !*s)
        return 0;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0)
        return 0;
    for (const char *p = s; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

void util_copy(char *dst, size_t dstsz, const char *src)
{
    if (dstsz == 0)
        return;
    size_t n = src ? strlen(src) : 0;
    if (n >= dstsz)
        n = dstsz - 1;
    if (n)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

void util_normalize_name(char *s)
{
    for (; *s; s++)
        if (*s == '-')
            *s = '_';
}

int util_read_file(const char *path, char *buf, size_t bufsz)
{
    if (bufsz == 0)
        return -1;
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    size_t n = fread(buf, 1, bufsz - 1, f);
    int err = ferror(f);
    fclose(f);
    if (err)
        return -1;
    buf[n] = '\0';
    while (n > 0 && isspace((unsigned char)buf[n - 1]))
        buf[--n] = '\0';
    return (int)n;
}

int util_path_join(char *dst, size_t dstsz, const char *a, const char *b,
                   const char *c)
{
    int n;
    if (c)
        n = snprintf(dst, dstsz, "%s/%s/%s", a, b, c);
    else
        n = snprintf(dst, dstsz, "%s/%s", a, b);
    return (n < 0 || (size_t)n >= dstsz) ? -1 : 0;
}

uint64_t util_fnv1a(uint64_t h, const void *data, size_t len)
{
    const unsigned char *p = data;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

void util_sanitize_field(char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            *s = ' ';
}
