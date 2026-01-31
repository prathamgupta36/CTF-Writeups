# Bitcoin (Crypto) Writeup

## Summary
The service implements an ElGamal-like decryption oracle on secp256k1, but it never validates that input points are on the curve. By submitting a point on a *singular* curve (specifically the curve with `B = 0`), the group law used by the server degenerates and allows recovering the secret key `d` from a single query. With `d`, Phase 2 decryption becomes straightforward.

## Challenge Recap
Server behavior:
- Phase 1: For each query, you send points `(C1, C2)`. The server returns:
  - `S = C2 - d * C1`
- Phase 2: It sends `(C1, C2)` where:
  - `C1 = k * G`
  - `C2 = P + k * Q` with `Q = d * G`
  - You must recover `P`.

The service prints a hint-like message and never validates that input points lie on the actual curve.

## Vulnerability: Invalid-Curve + Singular Curve Trick
The real curve is secp256k1:
```
y^2 = x^3 + 7 (mod p)
```

But there is no check that a submitted point satisfies this curve equation. If we send a point on the singular curve:
```
y^2 = x^3 (mod p)
```
then the usual elliptic curve addition formulas still execute. This particular curve is singular, so its group law is not elliptic. It degenerates into simple arithmetic on the parameter:

Let a point be expressed as:
```
P = (t^2, t^3)
```
Define:
```
u = x / y (mod p)
```
On the curve `y^2 = x^3`, the server's formula induces:
```
P1 + P2  <=>  u3 = u1 + u2 (mod p)
```
So scalar multiplication becomes:
```
[d]P  <=>  u_d = d * u (mod p)
```

### Recovering `d` from a single query
We submit:
```
C1 = C2 = P
```
Then the server returns:
```
S = C2 - d * C1 = (1 - d) * P
```
In parameter form:
```
S = (u_s) = (1 - d) * u
```
So:
```
d = 1 - u_s / u (mod p)
```
We can compute `u = x/y` and `u_s = x_s/y_s` from the returned point `S`.

## Solution Steps
1. Connect to the service and wait for Phase 1 prompt.
2. Choose a small `t` (e.g. `t = 2`), build a singular-curve point:
   - `P = (t^2, t^3)`
3. Send `C1 = C2 = P`, receive `S`.
4. Compute `d` via:
   - `u = x/y`, `u_s = x_s/y_s`
   - `d = 1 - u_s/u (mod p)`
5. Use valid curve points for the remaining Phase 1 queries to proceed.
6. For each Phase 2 round, recover:
   - `P = C2 - d * C1`
7. Send recovered `P` values and receive the flag.

## Solve Script
The script below automates the attack and prints the flag.

### Usage
```
./solve.py
# or
python3 solve.py
# optional: override host/port
python3 solve.py challenges3.ctf.sd 33196
```

### Script
See `solve.py`.

## Notes
- This is a classic invalid-curve attack, made even easier by accepting points on a singular curve.
- Only one oracle query is needed to recover `d`.
- After recovering `d`, Phase 2 decryption is standard EC ElGamal.
