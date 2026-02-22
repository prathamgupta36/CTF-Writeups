# Schwifty RSA :: 001 - Detailed Writeup

## Challenge Summary
The service generates a fresh RSA key with 64-bit primes (128-bit modulus), encrypts the flag in 16-byte chunks, and prints the public key plus ciphertexts. The attack is straightforward: factor the small modulus, compute the private key, and decrypt each chunk.

## Files and Interface
- `chall.py` contains the challenge logic.
- The remote service is exposed via `nc 159.65.255.102 30585`.

## Source Walkthrough
Key parts of `chall.py`:

1) Key generation
```
p, q = getPrime(64), getPrime(64)
n = p * q
e = 65537
d = inverse(e, (p - 1) * (q - 1))
```
This is standard RSA, but with 64-bit primes. That makes `n` only 128 bits, which is trivial to factor.

2) Chunked encryption
```
chunks = [flag[i:i+16] for i in range(0, len(flag), 16)]
m = bytes_to_long(chunk)
c = pow(m, e, n)
```
The flag is split into 16-byte blocks. Each block is converted to a big-endian integer and encrypted as `c = m^e mod n`.

3) Service output
Option 1 prints:
```
n = ...
e = 65537
ciphers = [c0, c1, c2, ...]
```
That is enough to recover the private key and decrypt.

## Cryptanalysis
RSA relies on the difficulty of factoring `n`. Here:
- `n` is 128 bits, which is far too small for security.
- Factoring with SymPy (`factorint`) or Pollard's Rho is fast.

Once `p` and `q` are known:
```
phi = (p - 1) * (q - 1)
d = e^{-1} mod phi
```
Then decrypt each ciphertext:
```
m = c^d mod n
```

## Implementation Notes
- The chunk size is 16 bytes. Since the plaintext is ASCII, `m` is comfortably below `n`, so there is no wrap-around risk.
- `long_to_bytes` returns the shortest representation. If a chunk ever had leading zero bytes, you would need to left-pad it back to 16 bytes. In this challenge, the flag does not include leading zero bytes, so a simple join works.

## Solver Script
```python
import socket, re
import sympy as sp
from Crypto.Util.number import long_to_bytes

HOST = "159.65.255.102"
PORT = 30585

# 1) Grab public data
s = socket.create_connection((HOST, PORT))
s.recv(4096)           # banner
s.sendall(b"1\n")
data = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
s.close()

text = data.decode()
n = int(re.search(r"n = (\d+)", text).group(1))
e = int(re.search(r"e = (\d+)", text).group(1))
ciphers = eval(re.search(r"ciphers = (\[.*\])", text).group(1))

# 2) Factor n
factors = sp.factorint(n)
p, q = list(factors.keys())

# 3) Compute private key
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# 4) Decrypt chunks and join
blocks = []
for c in ciphers:
    m = pow(c, d, n)
    b = long_to_bytes(m)
    # If you ever see missing bytes due to leading zeros:
    # b = b.rjust(16, b\"\\x00\")
    blocks.append(b)

plain = b\"\".join(blocks)
print(plain)
```

## Flag
```
flag{f2c963be-9856-483d-bd9c-9dcc3728ff5c}
```
