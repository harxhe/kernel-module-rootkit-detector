#ifndef KMRD_UTIL_H
#define KMRD_UTIL_H

#include <stddef.h>
#include <stdint.h>

#define UTIL_FNV_INIT 14695981039346656037ULL

/* Module names become path components under /sys/module, so only a safe
   character set is accepted: [A-Za-z0-9_.-]+, not "." or "..". */
int util_valid_module_name(const char *s);

/* strlcpy-style bounded copy; dst is always NUL terminated. */
void util_copy(char *dst, size_t dstsz, const char *src);

/* The kernel reports names with '_' even if the file on disk uses '-'. */
void util_normalize_name(char *s);

/* Read a small text file, strip trailing whitespace. Returns length or -1. */
int util_read_file(const char *path, char *buf, size_t bufsz);

/* Join path components into dst. Returns 0, or -1 if truncated. */
int util_path_join(char *dst, size_t dstsz, const char *a, const char *b,
                   const char *c);

uint64_t util_fnv1a(uint64_t h, const void *data, size_t len);

/* Replace control characters / tabs so a value is safe on one text line. */
void util_sanitize_field(char *s);

#endif /* KMRD_UTIL_H */
