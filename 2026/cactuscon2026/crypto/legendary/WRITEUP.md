# Legendary signs :: 001 - Writeup

## Challenge summary

We are given a "Legendary Cipher" that outputs a list of integers. The provided generator (from the zip) shows:

- A prime `p` (64-bit).
- A random `b` such that `legendre_symbol(b, p) = 1`.
- A public exponent `e = 65537`.
- For each plaintext bit:
  - compute `n = b^e mod p`.
  - output `n` for bit 1, and `-n mod p` for bit 0.

The remote service prints `b`, `p`, and the ciphertext list, and expects the flag back.

## Core observation

The encryption outputs **one of two classes** depending on the bit. The key idea is to recover those classes without the flag or secret key.

Let `n = b^e mod p`. For each bit:

- bit 1 -> output `n` (or another quadratic residue with the same sign behavior)
- bit 0 -> output `-n mod p`

If the ciphertexts are exactly `{n, p-n}`, then the two values can be mapped directly to bits.

However, the remote challenge uses a *randomized* variant: instead of always outputting the same `n`, it outputs **random quadratic residues for 1** and **random non-residues for 0**. The list length equals the number of bits, but the number of distinct values is large.

This leads to a clean, number-theoretic distinguisher.

## Legendre symbol distinguisher

The Legendre symbol tells whether a value is a quadratic residue modulo `p`:

```
legendre_symbol(x, p) = x^((p-1)/2) mod p
```

- If `p % 4 == 3`, then `legendre_symbol(-1, p) = -1`.
- Therefore, if `x` is a residue, then `-x` is a non-residue.

So for each ciphertext `c`:

- `legendre_symbol(c, p) == 1` -> bit 1
- `legendre_symbol(c, p) == -1` -> bit 0

This recovers the bitstring directly in the randomized case.

## Fallbacks for other cases

A robust solver should handle the non-randomized (two-value) generator too:

1. If only two distinct values are seen, then `p` can be recovered as `v1 + v2`.
2. If `b` and `p` are printed, compute `n = b^e mod p` and map `n` to 1 and `p-n` to 0.
3. If `p % 4 == 1`, the Legendre symbol cannot distinguish `x` and `-x` (both residues). In that case, decode both possible mappings and pick the one that looks like ASCII / contains `flag{`.

## Solution (solver)

The final solver uses this strategy:

1. Parse `p`, `b`, and the cipher list.
2. If `p % 4 == 3`, decode by Legendre symbol.
3. Otherwise, try all plausible two-class mappings and pick the best-looking plaintext.

The implementation is in `solve.py`.

## Running

```
python3 solve.py <host> <port>
```

or pipe the printed banner into stdin:

```
python3 solve.py < banner.txt
```

## Flag (from the remote instance in this session)

```
flag{03d3331d-62d0-47df-9ddd-74e0d49af077}
```
