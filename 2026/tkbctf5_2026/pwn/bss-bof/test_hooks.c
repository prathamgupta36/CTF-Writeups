#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

static int malloc_hook_hit;
static int free_hook_hit;
static void **malloc_hook_addr;
static void **free_hook_addr;

static void *my_malloc_hook(size_t size, const void *caller) {
  malloc_hook_hit = 1;
  fprintf(stderr, "malloc_hook size=%zu caller=%p\n", size, caller);
  *malloc_hook_addr = NULL;
  return malloc(size);
}

static void my_free_hook(void *ptr, const void *caller) {
  free_hook_hit = 1;
  fprintf(stderr, "free_hook ptr=%p caller=%p\n", ptr, caller);
  *free_hook_addr = NULL;
  free(ptr);
}

static void my_init_hook(void) {
  fprintf(stderr, "malloc_initialize_hook called\n");
}

int main(void) {
  void *sym;

  malloc_hook_addr = (void **)dlvsym(RTLD_DEFAULT, "__malloc_hook", "GLIBC_2.2.5");
  free_hook_addr = (void **)dlvsym(RTLD_DEFAULT, "__free_hook", "GLIBC_2.2.5");
  fprintf(stderr, "hook addrs malloc=%p free=%p\n", (void *)malloc_hook_addr,
          (void *)free_hook_addr);
  if (malloc_hook_addr) {
    *malloc_hook_addr = my_malloc_hook;
  }
  if (free_hook_addr) {
    *free_hook_addr = my_free_hook;
  }

  sym = dlvsym(RTLD_DEFAULT, "__malloc_initialize_hook", "GLIBC_2.2.5");
  if (sym) {
    *(void (**)(void))sym = my_init_hook;
    fprintf(stderr, "__malloc_initialize_hook addr=%p\n", sym);
  } else {
    fprintf(stderr, "dlvsym __malloc_initialize_hook failed: %s\n", dlerror());
  }

  void *p = malloc(0x40);
  fprintf(stderr, "malloc returned %p, malloc_hook_hit=%d\n", p, malloc_hook_hit);
  free(p);
  fprintf(stderr, "free_hook_hit=%d\n", free_hook_hit);
  return 0;
}
