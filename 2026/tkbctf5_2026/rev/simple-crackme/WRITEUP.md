# Simple Crackme — Writeup

- **CTF:** unknown / provided archive
- **Challenge:** `Simple Crackme`
- **Category:** Reverse Engineering
- **Points:** 233
- **Author:** `arata-nvm`

## TL;DR

The flag is:

```text
tkbctf{c00k13_1s_v3ry_t4sty_^q^}
```

---

## Files

The archive contains:

```text
simple-crackme/
├── flag.txt
└── simple-crackme
```

Quick triage:

```bash
$ file simple-crackme
simple-crackme: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ sha256sum simple-crackme
d0fbfacf5507f22c357df11191c46590c6fe945b611cf34f8d4e5676f4f0ee2b  simple-crackme
```

The bundled `flag.txt` is a decoy:

```text
tkbctf{dummy}
```

---

## 1. First look

The binary is stripped, but the imports are already interesting:

```bash
$ strings -a simple-crackme | grep -E 'flag|fopen|fopencookie|fgets|Correct|Wrong'
flag.txt
flag.txt not found
fopen
fgets
Correct
Wrong
```

And the dynamic imports include both `fopen` and `fopencookie`:

```bash
$ readelf -Ws simple-crackme
...
UND fopencookie@GLIBC_2.2.5
UND fopen@GLIBC_2.2.5
UND fgets@GLIBC_2.2.5
UND access@GLIBC_2.2.5
...
```

Running the original binary just crashes:

```bash
$ ./simple-crackme
Segmentation fault
```

So this is not a normal “type the flag into stdin” crackme. Static reversing is the right route.

---

## 2. Main logic

Disassembling the interesting code around `0x401440` shows the program does this:

1. Check that `flag.txt` exists.
2. Build the string `"flag.txt"` on the stack.
3. Prepare what is clearly a `cookie_io_functions_t` structure.
4. Open a custom stream.
5. `fgets()` one line from that stream.
6. Strip the trailing newline.
7. Run a verifier.
8. Print `Correct` or `Wrong`.

A slightly confusing detail: `objdump` labels the PLT call target as `fopen@plt`, but the call site is **not** using the `fopen` calling convention. It passes a `cookie_io_functions_t` struct by value on the stack, which is exactly how `fopencookie` is called on SysV AMD64 for a 32-byte struct argument. Dynamic binding confirms that this call resolves to `fopencookie`.

So the high-level behavior is effectively:

```c
if (access("flag.txt", F_OK) != 0) {
    puts("flag.txt not found");
    return 1;
}

FILE *fp = fopencookie(
    "flag.txt",
    "r",
    (cookie_io_functions_t){
        .read  = hidden_read,
        .write = 0,
        .seek  = 0,
        .close = 0,
    }
);

fgets(buf, 0x80, fp);
buf[strcspn(buf, "\n")] = 0;

if (check(buf))
    puts("Correct");
else
    puts("Wrong");
```

The important parts are:

- the program reads from **`flag.txt`**, not stdin;
- the stream uses a **hidden read callback**.

---

## 3. The visible checker at `0x4012d0`

The verifier at `0x4012d0` is easy to recover.

### 3.1 Length check

It first requires:

```c
strlen(input) == 0x20
```

So the real flag is exactly **32 bytes** long.

### 3.2 Packing into four 64-bit words

The next loop takes the 32-byte string and packs it into four little-endian 64-bit integers:

```c
q0 = u64(input[0:8])
q1 = u64(input[8:16])
q2 = u64(input[16:24])
q3 = u64(input[24:32])
```

### 3.3 Polynomial check

The `.data` section contains two arrays.

At `0x4040e0`:

```text
p = [1, 2, 3, 5, 7, 11, 13, 17]
```

At `0x4040a0`:

```text
0x8900970067058709
0x07dc2ccc8bad4997
0xcf63d5380c3d6c03
0xf893f11a1eb1c6ad
0x8cda2df4859a6a77
0xf2dc0ac7e0b7e32b
0xc82c335ca65e60f5
0x43df3465e0021399
```

The checker evaluates, for each `p_i`:

```text
q0 + p_i*q1 + p_i^2*q2 + p_i^3*q3   (mod 2^64)
```

and compares the result against the table above.

So the visible check is:

```python
for p_i, target_i in zip(P, TARGETS):
    assert (q0 + p_i*q1 + p_i*p_i*q2 + p_i*p_i*p_i*q3) & ((1<<64)-1) == target_i
```

### 3.4 CRC32 check

Finally, it computes CRC32 over the full 32-byte string and compares it with the dword at `0x404080`:

```text
0xc758a8ac
```

So the full visible constraint system is:

- 8 cubic equations modulo `2^64`
- plus
- `crc32(flag) == 0xc758a8ac`

---

## 4. Why the original binary segfaults

The reason the binary crashes is the hidden callback address.

Program headers:

```bash
$ readelf -l simple-crackme
...
LOAD  off 0x0000000000001000 vaddr 0x0000000000401000 filesz 0x00000000000005d0 memsz 0x00000000000005d0 R E
...
```

So the executable RX segment ends at file offset:

```text
0x1000 + 0x5d0 = 0x15d0
```

Now dump the raw file starting **right after** that:

```bash
$ dd if=simple-crackme bs=1 skip=$((0x15d0)) count=$((0x210)) of=hidden.bin
$ objdump -D -b binary -m i386:x86-64 --adjust-vma=0x4015d0 -Mintel hidden.bin
```

That extra blob contains two full functions:

- `0x4015d0` — a second verifier
- `0x401720` — the hidden stream read callback

Those bytes are present in the file, but **not covered by the RX LOAD segment**. The program still builds a `fopencookie` stream whose read callback points to `0x401720`, and the first `fgets()` eventually jumps there. On the unpatched binary, that causes the crash.

That is the anti-analysis trick of the challenge.

---

## 5. The hidden functions in the file gap

### 5.1 Hidden verifier at `0x4015d0`

The first hidden function is almost the same as the visible checker:

- it checks for length 32,
- packs 4 little-endian 64-bit words,
- evaluates the same cubic polynomial at `p = [1,2,3,5,7,11,13,17]`.

The only difference is that each target value is XOR-masked with:

```text
0x017f017f017f017f
```

The hidden checker does:

```text
target_i = DATA[i] ^ 0x017f017f017f017f
```

So the real target table is:

```text
0x887f967f667a8676
0x06a32db38ad248e8
0xce1cd4470d426d7c
0xf9ecf0651fcec7d2
0x8da52c8b84e56b08
0xf3a30bb8e1c8e254
0xc9533223a721618a
0x42a0351ae17d12e6
```

### 5.2 Hidden read callback at `0x401720`

The second hidden function is a custom `read` handler for `fopencookie`.

Its behavior is:

1. If the cookie still starts with `'f'`, it treats the cookie as the path string `"flag.txt"` and makes a raw syscall:
   - `syscall(2, cookie, 0, 0)` → `open(cookie, O_RDONLY, 0)`
2. It stores the returned file descriptor into the first byte of the cookie buffer.
3. It makes another raw syscall:
   - `syscall(0, fd, buf, size)` → `read(fd, buf, size)`
4. If the read succeeds and the buffer passes the **hidden checker**, it XORs the table at `0x4040a0` in place with `0x017f017f017f017f`, thereby deobfuscating the visible checker’s constants.

So the intended runtime flow was:

- read the real flag from `flag.txt`,
- validate it with the hidden verifier,
- unmask the visible table,
- then let `main` validate the same string again with the visible verifier,
- print `Correct`.

The bundled `flag.txt` is just a decoy, and the binary never actually reaches the callback on an unpatched run because of the broken segment mapping.

---

## 6. Static solve

Once the hidden verifier is recovered, the challenge becomes a constraint solve.

We want `q0..q3` such that for all

```text
p in [1,2,3,5,7,11,13,17]
```

we have

```text
q0 + p*q1 + p^2*q2 + p^3*q3 == target[p]   (mod 2^64)
```

with the deobfuscated target table above, and then:

```text
crc32(bytes(q0||q1||q2||q3)) == 0xc758a8ac
```

### 6.1 Why there are multiple algebraic solutions

If you only look at the cubic equations, the system is not uniquely invertible modulo `2^64`.

Using the first four `p` values gives a 4×4 Vandermonde matrix with determinant:

```text
(2-1)(3-1)(5-1)(3-2)(5-2)(5-3) = 48
```

Because we are solving modulo `2^64`, and:

```text
gcd(48, 2^64) = 16
```

there are **16** bit-vector solutions to the cubic system. The CRC32 check is what selects the real flag.

---

## 7. Solver script

This is the cleanest reproducer. It uses `z3-solver` to enumerate the 16 cubic solutions and then filters them by CRC32.

```python
#!/usr/bin/env python3
from z3 import BitVec, BitVecVal, Or, Solver
import zlib

MASK64 = (1 << 64) - 1
KEY = 0x017f017f017f017f
CRC_TARGET = 0xC758A8AC

# masked table from .data @ 0x4040a0
ENC_TARGETS = [
    0x8900970067058709,
    0x07DC2CCC8BAD4997,
    0xCF63D5380C3D6C03,
    0xF893F11A1EB1C6AD,
    0x8CDA2DF4859A6A77,
    0xF2DC0AC7E0B7E32B,
    0xC82C335CA65E60F5,
    0x43DF3465E0021399,
]

P = [1, 2, 3, 5, 7, 11, 13, 17]
TARGETS = [x ^ KEY for x in ENC_TARGETS]

q = [BitVec(f"q{i}", 64) for i in range(4)]
solver = Solver()

for p, y in zip(P, TARGETS):
    p64 = BitVecVal(p, 64)
    expr = q[0] + p64*q[1] + p64*p64*q[2] + p64*p64*p64*q[3]
    solver.add(expr == BitVecVal(y, 64))

sol_idx = 0
while solver.check().r == 1:
    m = solver.model()
    vals = [m[x].as_long() for x in q]
    candidate = b"".join(v.to_bytes(8, "little") for v in vals)

    print(f"[{sol_idx}] {candidate!r}")

    if (zlib.crc32(candidate) & 0xFFFFFFFF) == CRC_TARGET:
        print("\nFLAG:", candidate.decode())
        break

    solver.add(Or(*[x != m[x] for x in q]))
    sol_idx += 1
```

Expected result:

```text
FLAG: tkbctf{c00k13_1s_v3ry_t4sty_^q^}
```

---

## 8. Recovered flag chunks

The solver returns the four 64-bit little-endian chunks:

```text
q0 = 0x637b667463626b74
q1 = 0x73315f33316b3030
q2 = 0x34745f797233765f
q3 = 0x7d5e715e5f797473
```

Convert them back to bytes:

```text
tkbctf{c00k13_1s_v3ry_t4sty_^q^}
```

And a quick check shows the visible checker constants line up exactly:

```python
import zlib

flag = b"tkbctf{c00k13_1s_v3ry_t4sty_^q^}"
chunks = [int.from_bytes(flag[i:i+8], "little") for i in range(0, 32, 8)]
P = [1, 2, 3, 5, 7, 11, 13, 17]

vals = []
for p in P:
    v = (chunks[0] + p*chunks[1] + (p*p)*chunks[2] + (p*p*p)*chunks[3]) & ((1<<64)-1)
    vals.append(v)

for x in vals:
    print(hex(x))

print(hex(zlib.crc32(flag) & 0xffffffff))
```

This produces:

```text
0x887f967f667a8676
0x6a32db38ad248e8
0xce1cd4470d426d7c
0xf9ecf0651fcec7d2
0x8da52c8b84e56b08
0xf3a30bb8e1c8e254
0xc9533223a721618a
0x42a0351ae17d12e6
0xc758a8ac
```

Exactly the hidden targets plus the stored CRC.

---

## 9. Optional: patch the ELF so it actually runs

This part is not needed to get the flag, but it is a nice sanity check.

The crash happens because the RX LOAD segment stops at file offset `0x15d0`, right before the hidden functions.

If we patch the RX program header so that `p_filesz` and `p_memsz` cover the hidden blob as well, the callback becomes reachable and the binary starts behaving like a normal crackme.

### 9.1 Patcher

```python
#!/usr/bin/env python3
from pathlib import Path
import struct

path = Path("simple-crackme")
data = bytearray(path.read_bytes())

# Program header table starts at 0x40, each entry is 56 bytes.
# Entry #3 is the RX LOAD segment:
#   type=PT_LOAD, flags=PF_R|PF_X, off=0x1000, filesz=0x5d0, memsz=0x5d0
phoff = 0x40 + 3 * 56
ptype, flags, off, vaddr, paddr, filesz, memsz, align = struct.unpack_from(
    "<IIQQQQQQ", data, phoff
)

assert ptype == 1
assert flags == 5
assert off == 0x1000
assert filesz == 0x5D0
assert memsz == 0x5D0

# Hidden blob is in the file gap after 0x15d0; 0x820 is enough to cover it.
filesz = 0x820
memsz = 0x820

struct.pack_into(
    "<IIQQQQQQ",
    data,
    phoff,
    ptype, flags, off, vaddr, paddr, filesz, memsz, align,
)

out = Path("simple-crackme.patched")
out.write_bytes(data)
out.chmod(0o755)
print(f"wrote {out}")
```

### 9.2 Behavior after patching

With the bundled dummy flag:

```bash
$ ./simple-crackme.patched
Wrong
```

With the recovered real flag in `flag.txt`:

```bash
$ printf 'tkbctf{c00k13_1s_v3ry_t4sty_^q^}\n' > flag.txt
$ ./simple-crackme.patched
Correct
```

That validates the whole reversing chain end-to-end.

---

## 10. Final answer

```text
tkbctf{c00k13_1s_v3ry_t4sty_^q^}
```

---

## 11. Short version of the solve path

1. Reverse the visible checker at `0x4012d0`.
2. Notice the target table in `.data` looks inconsistent.
3. Compare the RX LOAD segment end (`0x15d0`) with raw file contents after it.
4. Recover the hidden verifier at `0x4015d0` and hidden read callback at `0x401720`.
5. See that the hidden verifier uses the same cubic system, but XOR-unmasks the target table with `0x017f017f017f017f`.
6. Solve the 64-bit bit-vector equations.
7. Use CRC32 `0xc758a8ac` to pick the unique valid flag.
8. Optionally patch the ELF header to make the runtime path work and verify the solution.

