#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

static int (*real_memcmp)(const void *, const void *, size_t);

static void dump_hex(const char *label, const unsigned char *buf, size_t n) {
    fprintf(stderr, "%s %zu\n", label, n);
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, "%02x", buf[i]);
        if ((i + 1) % 32 == 0 || i + 1 == n) {
            fputc('\n', stderr);
        }
    }
}

int memcmp(const void *s1, const void *s2, size_t n) {
    if (!real_memcmp) {
        real_memcmp = dlsym(RTLD_NEXT, "memcmp");
    }
    dump_hex("memcmp-left", (const unsigned char *)s1, n);
    dump_hex("memcmp-right", (const unsigned char *)s2, n);
    return real_memcmp(s1, s2, n);
}
