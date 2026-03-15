# Hour of Joy Writeup

## Challenge

**Category:** Pwn  
**Points:** 748

Challenge text:

> This program is very friendly. It just wants to say hello. Nothing suspicious going on here at all. Download the binary and run it locally.

Files in the challenge:

- `vuln`
- `DESCRIPTION.md`

## Initial Recon

`checksec` on the binary:

```text
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

The binary is not stripped, which makes the first pass straightforward. The interesting symbols are:

- `main`
- `setup`
- `print_flag`

## Reversing

Disassembling `main` shows the core logic:

1. `setup()` disables buffering.
2. A local variable is initialized to `0xdeadbeef`.
3. The program asks for a name using `fgets`.
4. It prints `Hello, ` and then calls `printf(name)`.
5. It asks for a secret code using `scanf("%d", &code)`.
6. If `code == 0xdeadbeef`, it calls `print_flag()`.

Relevant behavior in pseudocode:

```c
int main(void) {
    setup();

    int target = 0xdeadbeef;
    char name[0x40];
    int code;

    printf("What is your name? ");
    fgets(name, 0x40, stdin);
    name[strcspn(name, "\n")] = '\0';

    printf("Hello, ");
    printf(name);                     // format-string bug
    puts("!");

    printf("Enter the secret code: ");
    scanf("%d", &code);

    if (code == target) {
        print_flag();
    } else {
        puts("Wrong! Nice try.");
    }
}
```

There is a real format-string vulnerability in `printf(name)`, and that is probably the intended hint from the flag text. But for solving the challenge, it is not necessary.

## The Actual Solve

The program reads the secret using:

```c
scanf("%d", &code);
```

`%d` parses a **signed 32-bit decimal integer**.  
The comparison value is `0xdeadbeef`, which as a signed 32-bit integer is:

```text
0xdeadbeef = -559038737
```

So the simplest solve is:

1. Enter any name.
2. Enter `-559038737` as the secret code.

That satisfies the comparison and jumps directly to `print_flag()`.

## Flag Recovery

Running the program locally:

```text
What is your name? test
Hello, test!
Enter the secret code: -559038737
utflag{f0rm4t_str1ng_l34k3d}
```

Flag:

```text
utflag{f0rm4t_str1ng_l34k3d}
```

## About `print_flag`

`print_flag()` stores an encoded byte array on the stack and XORs each byte with `0x42` before printing it. So even without satisfying the check, the flag can be recovered statically from the binary by decoding those bytes.

## Solver Script

A small local/remote solver is included in this repo:

- `solve.py`

Usage:

```bash
python3 ./solve.py
```

For a remote service:

```bash
python3 ./solve.py REMOTE HOST=example.com PORT=31337
```

## Summary

This challenge looks like a format-string pwn, and it does contain one. But the easiest path is simpler: the secret is compared against `0xdeadbeef` while input is parsed with signed `%d`, so sending `-559038737` wins immediately.
