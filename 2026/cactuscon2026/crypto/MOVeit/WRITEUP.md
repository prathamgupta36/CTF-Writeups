MOVeit :: 001 - Crypto (150)
================================

Goal
----
Recover the AES key derived from the ECDH shared secret and decrypt the flag.

Challenge summary
-----------------
The server prints:
- An elliptic curve over F_p: y^2 = x^3 + a*x + b
- Generator G
- Alice public key P1 = n_a * G
- Bob public key P2 = n_b * G
- AES-ECB ciphertext of the flag using key = str(Sx)[:16], where S = n_a * P2

We must recover n_a (or directly Sx) from the public values.

Key observation: supersingular curve
------------------------------------
Parameters:
- p = 14537114296651069957 (prime)
- a = -30, b = 56

Compute the j-invariant:
    j = 1728 * 4*a^3 / (4*a^3 + 27*b^2) mod p = 8000

This curve is a known CM curve with j = 8000. For primes p ≡ 5 (mod 8),
the curve is supersingular and has trace t = 0, so:
    #E(F_p) = p + 1

Indeed p % 8 = 5, so the group order is:
    n = p + 1 = 14537114296651069958
    n = 2 * 172981 * 42019396051159

The server’s generator G has full order n.

Exploit: Pohlig–Hellman
-----------------------
Since n is smooth-ish (product of three primes), use Pohlig–Hellman:

For each factor q:
1) Compute G_q = (n/q) * G and P1_q = (n/q) * P1
2) Solve discrete log P1_q = d * G_q (mod q)
   - For small q (2 and 172981): brute force.
   - For large q (42019396051159): baby-step/giant-step (BSGS).
3) Combine the residues with CRT to recover n_a modulo n.

With n_a recovered:
    S = n_a * P2
    key = str(Sx)[:16]
    flag = AES-ECB-Decrypt(ciphertext, key)

Complexity
----------
The largest factor is ~4.2e13. BSGS needs about sqrt(q) ≈ 6.5e6
steps and a hash table of that size. This is feasible in Python in
~1 minute with a few hundred MB of RAM.

Solve script
------------
File: solve.py

It:
- Connects to the challenge service (or reads saved output / stdin)
- Parses G, P1, P2, ciphertext
- Computes n_a via Pohlig–Hellman + BSGS
- Derives the AES key and decrypts the flag

Usage:
  python3 solve.py
  python3 solve.py --host 159.65.255.102 --port 31968
  nc 159.65.255.102 31968 | python3 solve.py
  python3 solve.py --file output.txt

Expected output:
  flag{a4b03ecc-9f3e-47ff-b749-b650f713504c}
