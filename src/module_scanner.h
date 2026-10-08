#ifndef MOD_SCANNER_H
#define MOD_SCANNER_H

#define MAX_MODULE_NAME 64

typedef struct {
    char name[MAX_MODULE_NAME];
    unsigned long size;
    unsigned long ref_count;
    char deps[256];
} module_info_t;

#endif /* MOD_SCANNER_H */