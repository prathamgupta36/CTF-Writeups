# sisyphus (crypto)

## Summary
The challenge is a tiny garbled-circuit service for an AND gate. It prints the two input labels for our chosen input, three encrypted table rows (the (0,0) row is omitted), and the IV used by the block cipher. We must submit the output label corresponding to logical `1` to get the flag.

The intended security breaks because the IV is generated in a *default argument* (`def __init__(..., iv=get_random_bytes(8))`). In Python, default arguments are evaluated once at function definition time, so every gate encryption within a run reuses the same IV. That makes the CTR keystream for a given key constant across all rows, which allows us to solve for the missing output label.

## Relevant Code
From `server.py`:
- `Cipher.__init__(..., iv=get_random_bytes(8))` causes a fixed IV for the whole run.
- Garbling uses AES-CTR twice (`AES.new(key1, ..., nonce=iv)` then `AES.new(key2, ..., nonce=iv)`), so the final ciphertext is:

```
C = P XOR KS(key1, iv) XOR KS(key2, iv)
```

Here `P` is the output label key, and `KS` is the CTR keystream for a key and the fixed IV.

The (0,0) input row is the all-zero ciphertext (GRR3), so it is *known* even though it is not printed.

## Attack Outline
Let:
- `A0` be the label key for wire 0, value 0 (this is always our input).
- `B0`/`B1` be the label keys for wire 1, values 0 and 1.
- `C0`/`C1` be the output labels for values 0 and 1.
- `sA0`, `sA1`, `sB0`, `sB1` be CTR keystreams for those keys (constant because IV is constant).

Each row encryption looks like:

```
CT(va, vb) = C_{va AND vb} XOR sA{va} XOR sB{vb}
```

Because the `(0,0)` row is GRR3, `CT(0,0) = 0` is known. We also know `A0` and exactly one of `B0`/`B1` (depending on our chosen input), so we can compute `C0` from the row for our actual input, then solve for all keystreams and finally recover `C1`.

### Step-by-step
1. Parse the printed labels for our chosen inputs, the three printed ciphertext rows, and the IV.
2. Compute `sA0 = KS(A0, iv)` and `sB_t = KS(B_t, iv)` for our chosen input label on wire 1.
3. Use the row matching our actual input `(0, t)` to recover `C0`:
   `C0 = CT(0,t) XOR sA0 XOR sB_t`.
4. Use rows `(0,0)` and `(0,1)` (one is all-zero) to solve for `sB0` and `sB1`:
   `sB0 = CT(0,0) XOR C0 XOR sA0`,
   `sB1 = CT(0,1) XOR C0 XOR sA0`.
5. Use row `(1,0)` to solve for `sA1`:
   `sA1 = CT(1,0) XOR C0 XOR sB0`.
6. Use row `(1,1)` to recover `C1`:
   `C1 = CT(1,1) XOR sA1 XOR sB1`.
7. Submit `C1` (hex) to the server to get the flag.

## Exploit Script
The following script implements the above logic and works for `your_choice` equal to 0 or 1.

```python
import socket, re
from Crypto.Cipher import AES

HOST, PORT = "chall.lac.tf", 31182
CHOICE = 0  # 0 or 1 works

def xor3(a, b, c):
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))

s = socket.create_connection((HOST, PORT))
f = s.makefile("rb", buffering=0)

buf = b""
while b"decide your fate: " not in buf:
    chunk = f.read(1)
    if not chunk:
        raise SystemExit("connection closed early")
    buf += chunk

s.sendall(f"{CHOICE}\n".encode())

wire_labels = []
rows = {}
row_order = [(0, 1), (1, 0), (1, 1)]
row_idx = 0
iv = None

while True:
    line = f.readline()
    if not line:
        raise SystemExit("connection closed before iv")
    line = line.decode().strip()
    if line.startswith("wire "):
        m = re.match(r"wire (\d+): ([0-9a-f]+) ([01])", line)
        if m:
            wire_labels.append((bytes.fromhex(m.group(2)), int(m.group(3))))
    elif line.startswith("iv: "):
        iv = bytes.fromhex(line.split()[1])
        break
    elif re.match(r"^[0-9a-f]+ [01]$", line):
        ct_hex, _ = line.split()
        rows[row_order[row_idx]] = bytes.fromhex(ct_hex)
        row_idx += 1

A0_key, A0_ptr = wire_labels[0]
B_key, B_ptr = wire_labels[1]

p0 = A0_ptr
p1 = B_ptr if CHOICE == 0 else (B_ptr ^ 1)

zero_ct = b"\x00" * 16

def ct(pair):
    return zero_ct if pair == (0, 0) else rows[pair]

def ks(key):
    return AES.new(key, AES.MODE_CTR, nonce=iv).encrypt(b"\x00" * 16)

sA0 = ks(A0_key)
sBt = ks(B_key)

# output label for 0
C0 = xor3(ct((p0, p1 ^ CHOICE)), sA0, sBt)

# keystreams for B0/B1
sB0 = xor3(ct((p0, p1)), C0, sA0)
sB1 = xor3(ct((p0, p1 ^ 1)), C0, sA0)

# keystream for A1
sA1 = xor3(ct((p0 ^ 1, p1)), C0, sB0)

# output label for 1
C1 = xor3(ct((p0 ^ 1, p1 ^ 1)), sA1, sB1)

s.sendall((C1.hex() + "\n").encode())
print(f.read().decode(errors="ignore"))
```

## Flag
```
lactf{m4yb3_h3_w4s_h4ppy_aft3r_4all}
```
