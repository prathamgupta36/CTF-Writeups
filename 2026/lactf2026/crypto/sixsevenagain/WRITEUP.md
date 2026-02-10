# Six Seven Again - Writeup

## Challenge Summary

The challenge generates RSA with:

- `q` a random 670-bit prime,
- `p` a special 201-digit prime with the decimal form:

```
p = 66...66 || (67 random digits from {6,7}) || 77...77
```

That is, 67 leading `6` digits, then 67 digits from `{6,7}`, then 67 trailing `7` digits.

We are given `n = p*q` and `c = m^e mod n` with `e = 65537`.

Goal: recover the flag (plaintext).

## Key Observation

Write `p` as:

```
p = K + 10^67 * x
```

Where:

- `x` is the middle 67 digits (each digit is `6` or `7`), so `0 <= x < 10^67`.
- `K` is the fixed constant formed by the prefix and suffix digits:
  - 67 leading `6` digits and 67 trailing `7` digits.

This makes `p` an *affine function* of a small unknown `x`.

Since `p | n`, we have:

```
K + 10^67 * x ≡ 0 (mod p)
```

Equivalently, over `mod n`:

```
x + (K * inv(10^67)) ≡ 0 (mod p)
```

So `x` is a small root of a degree-1 polynomial modulo a large composite:

```
f(x) = x + b  (mod n)
```

with `b = K * inv(10^67) mod n`, and `|x| < 10^67`.

This is a classic Coppersmith/Howgrave-Graham small-root case for a linear polynomial with an unknown factor of `n` as modulus. We only need one small root to recover `p` via `gcd(10^67*x + K, n)`.

## Solving Strategy

1. Build `f(x) = x + b (mod n)` where:

   ```
   b = K * inv(10^67) mod n
   ```

2. Use the Howgrave-Graham univariate Coppersmith method for `d = 1` with:

   - `beta = 0.5` (since `p` is roughly `n^0.5`)
   - `X = 10^67`
   - `m = 4`, `t = 4` (standard parameters that work here)

3. Recover the small root `x`.

4. Compute:

   ```
   p = gcd(10^67 * x + K, n)
   q = n / p
   ```

5. Decrypt with RSA:

   ```
   d = e^{-1} mod (p-1)(q-1)
   m = c^d mod n
   ```

## Result

The recovered flag is:

```
lactf{n_h4s_1337_b1ts_b3c4us3_667+670=1337}
```

## Implementation Notes

The included solver script `solve.py`:

- Connects to the server,
- Solves the PoW,
- Extracts `n, c`,
- Runs Howgrave-Graham Coppersmith via `fpylll` LLL,
- Recovers `p, q`,
- Decrypts the flag.

LLL parameters are tiny (dimension 8), so it is fast.

