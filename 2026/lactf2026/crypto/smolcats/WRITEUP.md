# smol cats (crypto)

## Challenge
The service prints an RSA modulus `n`, public exponent `e = 65537`, and ciphertext `c`, then asks for the plaintext integer:

```
n = ...
e = 65537
c = ...
```

The description hints that the cat used "tiny primes" to build `n`, so the RSA modulus is intentionally weak.

## Solution
RSA decryption requires the private exponent `d`, which is the modular inverse of `e` modulo `phi(n)`. To compute `phi(n)`, we must factor `n` into its prime factors.

Because `n` is only ~200 bits and built from small primes, it is feasible to factor quickly. I used PARI/GP (via `cypari2`) to compute `factorint(n)`, which returns the prime factors of `n`.

Once we have the factorization:

```
phi(n) = (p1 - 1) * p1^(e1 - 1) * (p2 - 1) * p2^(e2 - 1) * ...
```

Then compute:

```
d = e^{-1} mod phi(n)
m = c^d mod n
```

The value `m` is the plaintext integer the service expects. Send it back to the service to receive the flag.

## Example solve script

```python
import socket
import re
from cypari2 import Pari

pari = Pari()
pari.allocatemem(128_000_000)

HOST = "chall.lac.tf"
PORT = 31224

s = socket.create_connection((HOST, PORT))

buf = b""
while True:
    data = s.recv(4096)
    if not data:
        break
    buf += data
    if b"How many treats do I want?" in buf:
        break

text = buf.decode(errors="ignore")
nums = re.findall(r"([nec])\s*=\s*(\d+)", text)
vals = {k: int(v) for k, v in nums}

n = vals["n"]
e = vals["e"]
c = vals["c"]

primes = pari(f"factorint({n})[,1]")
exps = pari(f"factorint({n})[,2]")
ps = [int(primes[i]) for i in range(primes.length())]
qs = [int(exps[i]) for i in range(exps.length())]

phi = 1
for p, exp in zip(ps, qs):
    phi *= (p - 1) * (p ** (exp - 1))

d = pow(e, -1, phi)
m = pow(c, d, n)

s.sendall(str(m).encode() + b"\n")

print(s.recv(4096).decode(errors="ignore"))
```

## Flag

```
lactf{sm0l_pr1m3s_4r3_n0t_s3cur3}
```
