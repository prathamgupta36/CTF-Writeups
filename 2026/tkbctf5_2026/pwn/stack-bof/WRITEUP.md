# Stack BOF Writeup

## Challenge

The binary is tiny:

```c
int main() {
  char buf[8];
  uint64_t* dest = 0;
  printf("printf: %p\n", printf);

  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}
```

Protections on the challenge binary:

- Full RELRO
- PIE
- NX
- Stack canary

At first glance this looks like a normal stack overflow, but the canary blocks the obvious ret2libc path.

## What We Control

The program gives us three useful primitives in one connection:

1. A libc leak via `printf("printf: %p\n", printf)`.
2. One arbitrary 8-byte write:
   - first `read` gives us `dest`
   - second `read` writes 8 bytes to `*dest`
3. A stack overflow via `gets(buf)` on an 8-byte buffer.

If there were no canary, the solution would be immediate:

- leak libc
- overflow the stack
- return into `system("/bin/sh")`

The real problem is how to satisfy the stack canary without a stack leak.

## Key Idea

On x86_64 glibc, the current stack canary is stored in thread-local storage at `fs:0x28`.

The important observation is that the stack check at function epilogue does not care what the canary used to be. It only checks that:

- the copy saved on the stack when `main` started
- matches the current TLS canary in `fs:0x28`

So instead of leaking the canary, we can overwrite the TLS canary itself with a known value using the arbitrary write.

Then we send an overflow payload that places the same known value in the stack canary slot. The check passes, and control returns into our ROP chain.

That turns the problem from "how do I leak the canary?" into "where is TLS relative to the leaked libc?"

## Finding TLS

Locally, using the exact runtime from the provided Docker image, the loader sets `fs_base` with:

```text
arch_prctl(ARCH_SET_FS, ...)
```

Sampling many runs showed:

- `fs_base - libc_base` keeps low bits `0x740`
- the offset varies by page
- under the real Ubuntu 24.04 runtime it falls in a brute-forceable window

That means after leaking libc we can guess:

```text
tls_base = libc_base + delta
```

and try to write our chosen canary to:

```text
tls_base + 0x28
```

Each connection is independent, so a wrong guess just crashes that attempt. A correct guess gives a clean canary bypass and our ROP chain runs.

## Exact Runtime Matters

This challenge ships a Docker image based on `ubuntu:24.04`, and the offsets mattered.

I extracted the exact `libc.so.6` and `ld-linux-x86-64.so.2` from the built image and used them for:

- gadget offsets
- `/bin/sh` offset
- local validation of the TLS layout

Without matching the remote runtime, the local measurements are misleading.

## ROP Chain

Once the canary is under control, the payload is standard ret2libc:

```text
padding
known canary
saved rbp filler
ret
pop rdi ; ret
"/bin/sh"
system
exit
```

The extra `ret` keeps stack alignment sane for `system`.

## Exploit Flow

For each connection:

1. Read the leaked `printf` address.
2. Compute `libc_base`.
3. Choose a candidate `delta`.
4. Arbitrary-write `NEW_CANARY` to `libc_base + delta + 0x28`.
5. Send the `gets` payload with the same canary and the ret2libc chain.
6. Run `echo __PWNED__ ; cat /flag* ; exit`.

If the TLS guess is wrong, the process dies.
If the guess is right, the canary check passes and the command runs.

Because every delta guess is independent, parallel brute force works well.

## Final Solver

The final solver is in `solve.py`. Important details:

- it uses the extracted challenge libc/ld when present
- it brute-forces TLS deltas in parallel
- it skips payloads containing `\n`, because `gets` would stop early
- it uses a known canary value:

```python
NEW_CANARY = 0x4242424241414141
```

Run it with:

```bash
python3 solve.py REMOTE WORKERS=16
```

## Result

The exploit returns:

```text
__PWNED__
tkbctf{*** stack smashing not detected ***}
```

## Takeaway

This is a good example of a common trap in small pwn challenges:

- the stack canary makes the direct overflow look dead
- but the program also gives a write primitive
- so the correct target is not the stack copy of the canary, but the TLS source of truth

Once that is recognized, the challenge becomes a libc/TLS address problem plus a normal ret2libc.
