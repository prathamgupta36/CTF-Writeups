#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

static int (*real_open)(const char *pathname, int flags, ...);
static int (*real_openat)(int dirfd, const char *pathname, int flags, ...);
static FILE *(*real_fopen)(const char *pathname, const char *mode);
static FILE *(*real_popen)(const char *command, const char *type);
static int (*real_system)(const char *command);
static int (*real_execve)(const char *pathname, char *const argv[], char *const envp[]);
static int (*real_posix_spawn)(
    pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]);
static ssize_t (*real_read)(int fd, void *buf, size_t count);
static char *(*real_gets)(char *s);

int codecvt_probe_impl(void *fp, void *rsp, void *rbp, void *rax, void *rbx,
                       void *r12) {
  unsigned long long stack_qword = 0;
  void *ptr_at_rbp_minus_78 = NULL;

  if (rbp) {
    memcpy(&stack_qword, (char *)rbp - 0x78, sizeof(stack_qword));
    ptr_at_rbp_minus_78 = (void *)stack_qword;
  }
  dprintf(2,
          "[trace] codecvt_probe fp=%p rsp=%p rbp=%p rax=%p rbx=%p r12=%p "
          "[rbp-0x78]=%p\n",
          fp, rsp, rbp, rax, rbx, r12, ptr_at_rbp_minus_78);
  return -1;
}

__attribute__((naked)) int codecvt_probe(void *fp) {
  __asm__(
      "mov %rsp, %rsi\n\t"
      "mov %rbp, %rdx\n\t"
      "mov %rax, %rcx\n\t"
      "mov %rbx, %r8\n\t"
      "mov %r12, %r9\n\t"
      "jmp codecvt_probe_impl\n\t");
}

__attribute__((constructor)) static void announce_probe(void) {
  dprintf(2, "[trace] codecvt_probe_addr=%p\n", codecvt_probe);
}

static void init_real(void) {
  if (!real_open) {
    real_open = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_popen = dlsym(RTLD_NEXT, "popen");
    real_system = dlsym(RTLD_NEXT, "system");
    real_execve = dlsym(RTLD_NEXT, "execve");
    real_posix_spawn = dlsym(RTLD_NEXT, "posix_spawn");
    real_read = dlsym(RTLD_NEXT, "read");
    real_gets = dlsym(RTLD_NEXT, "gets");
  }
}

static void log_line(const char *kind, const char *arg1, const char *arg2) {
  char buf[1024];
  int n;

  init_real();
  if (arg2) {
    n = snprintf(buf, sizeof(buf), "[trace] %s %s %s\n", kind, arg1 ? arg1 : "(null)",
                 arg2);
  } else {
    n = snprintf(buf, sizeof(buf), "[trace] %s %s\n", kind, arg1 ? arg1 : "(null)");
  }
  if (n > 0) {
    write(2, buf, (size_t)n);
  }
}

int open(const char *pathname, int flags, ...) {
  mode_t mode = 0;
  va_list ap;

  init_real();
  if (flags & O_CREAT) {
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);
  }
  log_line("open", pathname, NULL);
  if (flags & O_CREAT) {
    return real_open(pathname, flags, mode);
  }
  return real_open(pathname, flags);
}

int openat(int dirfd, const char *pathname, int flags, ...) {
  mode_t mode = 0;
  va_list ap;

  init_real();
  if (flags & O_CREAT) {
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);
  }
  log_line("openat", pathname, NULL);
  if (flags & O_CREAT) {
    return real_openat(dirfd, pathname, flags, mode);
  }
  return real_openat(dirfd, pathname, flags);
}

FILE *fopen(const char *pathname, const char *mode) {
  init_real();
  log_line("fopen", pathname, mode);
  return real_fopen(pathname, mode);
}

FILE *popen(const char *command, const char *type) {
  init_real();
  log_line("popen", command, type);
  return real_popen(command, type);
}

int system(const char *command) {
  init_real();
  log_line("system", command, NULL);
  return real_system(command);
}

int execve(const char *pathname, char *const argv[], char *const envp[]) {
  init_real();
  log_line("execve", pathname, NULL);
  return real_execve(pathname, argv, envp);
}

int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *attrp, char *const argv[], char *const envp[]) {
  init_real();
  log_line("posix_spawn", path, NULL);
  return real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

ssize_t read(int fd, void *buf, size_t count) {
  char line[256];
  int n;

  init_real();
  n = snprintf(line, sizeof(line), "[trace] read fd=%d buf=%p count=%zu\n", fd, buf, count);
  if (n > 0) {
    write(2, line, (size_t)n);
  }
  return real_read(fd, buf, count);
}

char *gets(char *s) {
  unsigned long long read_ptr;
  unsigned long long read_end;
  unsigned long long buf_base;
  unsigned long long buf_end;
  unsigned long long vtable;

  init_real();
  memcpy(&read_ptr, (char *)stdin + 0x08, sizeof(read_ptr));
  memcpy(&read_end, (char *)stdin + 0x10, sizeof(read_end));
  memcpy(&buf_base, (char *)stdin + 0x38, sizeof(buf_base));
  memcpy(&buf_end, (char *)stdin + 0x40, sizeof(buf_end));
  memcpy(&vtable, (char *)stdin + 0xd8, sizeof(vtable));
  dprintf(2,
          "[trace] gets stdin=%p read_ptr=%#llx read_end=%#llx buf_base=%#llx "
          "buf_end=%#llx vtable=%#llx\n",
          (void *)stdin, read_ptr, read_end, buf_base, buf_end, vtable);
  return real_gets(s);
}
