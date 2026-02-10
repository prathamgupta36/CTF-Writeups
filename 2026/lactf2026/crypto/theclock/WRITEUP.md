# The Clock - Writeup

## Overview
The challenge implements a Diffie-Hellman-style key exchange over the group of
solutions to `x^2 + y^2 = 1 (mod p)` with the "clock addition" law:

```
(x1, y1) + (x2, y2) = (x1*y2 + y1*x2, y1*y2 - x1*x2)  (mod p)
```

The task is to recover the shared secret from the provided public keys and
decrypt the AES-ECB ciphertext.

## Key Observations
1. Every valid point `(x, y)` in this group satisfies `x^2 + y^2 = 1 (mod p)`.
2. The modulus `p` is not given, but all printed public points lie on the same
   curve, so:
   ```
   p | (x^2 + y^2 - 1)
   ```
   for each point. Therefore, `p` is the gcd of those values.
3. For `p ≡ 3 (mod 4)`, the group of unit-circle points has order `p + 1`.
4. `p + 1` factors into many small primes, so Pohlig–Hellman applies.
5. The shared secret is `a * BobPublic`, and the AES key is
   `md5(f"{x},{y}")`.

## Recovering p
Compute:

```
N1 = base_x^2 + base_y^2 - 1
N2 = alice_x^2 + alice_y^2 - 1
N3 = bob_x^2 + bob_y^2 - 1
p = gcd(N1, N2, N3)
```

This yields:

```
p = 13767529254441196841515381394007440393432406281042568706344277693298736356611
```

`p` is prime and `p ≡ 3 (mod 4)`, so the group order is `p + 1`.

## Pohlig–Hellman Outline
Factor:

```
p + 1 = 2^2 * 39623 * 41849 * 42773 * 46511 * 47951 * 50587 * 50741
         * 51971 * 54983 * 55511 * 56377 * 58733 * 61843 * 63391 * 63839 * 64489
```

For each prime power `q^e`, compute:

```
g_i = (p+1)/q^e * G
h_i = (p+1)/q^e * A
```

Solve `d_i` from `g_i * d_i = h_i` with BSGS in the subgroup of order `q^e`.
Combine all `d_i` with CRT to get Alice's secret `a`.

## Decryption
Compute the shared point:

```
S = a * BobPublic
key = md5(f"{S.x},{S.y}").digest()
```

Decrypt with AES-ECB and unpad:

```
flag = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
```

Result:

```
lactf{t1m3_c0m3s_f4r_u_4all}
```

## Minimal Solver (Reference)
```python
from math import isqrt
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

p = 13767529254441196841515381394007440393432406281042568706344277693298736356611
n = p + 1

base = (13187661168110324954294058945757101408527953727379258599969622948218380874617,
        5650730937120921351586377003219139165467571376033493483369229779706160055207)
alice = (13109366899209289301676180036151662757744653412475893615415990437597518621948,
         5214723011482927364940019305510447986283757364508376959496938374504175747801)
bob = (1970812974353385315040605739189121087177682987805959975185933521200533840941,
       12973039444480670818762166333866292061530850590498312261363790018126209960024)

factors = {
  2:2, 39623:1, 41849:1, 42773:1, 46511:1, 47951:1, 50587:1, 50741:1,
  51971:1, 54983:1, 55511:1, 56377:1, 58733:1, 61843:1, 63391:1, 63839:1, 64489:1
}

def add(P,Q):
    x1,y1 = P; x2,y2 = Q
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def inv(P):
    x,y = P
    return ((-x) % p, y)

def scalarmult(P,n):
    R = (0,1)
    Q = P
    while n:
        if n & 1:
            R = add(R,Q)
        Q = add(Q,Q)
        n >>= 1
    return R

def dlog_bsgs(g,h,m):
    m1 = isqrt(m) + 1
    table = {}
    acc = (0,1)
    for j in range(m1):
        if acc not in table:
            table[acc] = j
        acc = add(acc,g)
    g_m = scalarmult(g, m1)
    g_m_inv = inv(g_m)
    gamma = h
    for i in range(m1+1):
        if gamma in table:
            return i*m1 + table[gamma]
        gamma = add(gamma, g_m_inv)
    raise ValueError("log not found")

def crt(residues, moduli):
    x = 0
    M = 1
    for m in moduli:
        M *= m
    for r,m in zip(residues, moduli):
        Mi = M // m
        invMi = pow(Mi, -1, m)
        x = (x + r * Mi * invMi) % M
    return x

residues = []
moduli = []
for q,e in factors.items():
    m_i = q**e
    g_i = scalarmult(base, n//m_i)
    h_i = scalarmult(alice, n//m_i)
    d_i = dlog_bsgs(g_i, h_i, m_i)
    residues.append(d_i)
    moduli.append(m_i)

a = crt(residues, moduli)
shared = scalarmult(bob, a)
key = md5(f"{shared[0]},{shared[1]}".encode()).digest()

ct = bytes.fromhex("d345a465538e3babd495cd89b43a224ac93614e987dfb4a6d3196e2d0b3b57d9")
pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16)
print(pt)
```
