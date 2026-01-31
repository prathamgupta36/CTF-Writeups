# DORYA (crypto, 120)

## Summary
We are given 7 RSA encryptions with the same exponent `e = 7`, but each time the plaintext `m` is first transformed by a linear fractional map:

```
(a_i m + b_i) * (c_i m + d_i)^{-1} mod n_i
```

The coefficients `(a_i, b_i, c_i, d_i)` are known and evolve deterministically. Each encryption yields a degree‑7 polynomial congruence in `m`. Combining all 7 congruences with CRT gives a single polynomial `f(x) ≡ 0 (mod N)` where `N = Π n_i`. Since `N` is ~7165 bits and `m` is a short flag (~< 2^700), this is a classic small‑root instance. Coppersmith’s method (Howgrave‑Graham univariate) plus LLL gives a polynomial `h(x)` that has the same small integer root. We then recover the root by CRT‑lifting roots of `h(x)` modulo many primes and verify it in `f(x)`.

Recovered flag:

```
0xL4ugh{long_long_long_long_long_long_long_long_long_long_long_flag56af09d36f}
```

---

## Derivation
From `chall.py`, each round returns:

```
num = a*m + b
den = c*m + d
padded_m = num * den^{-1} mod n
c = padded_m^e mod n
```

Rearrange for each sample `(n_i, c_i)`:

```
(a_i m + b_i)^e ≡ c_i * (c_i m + d_i)^e  (mod n_i)
```

Define the polynomial

```
f_i(x) = (a_i x + b_i)^e - c_i * (c_i x + d_i)^e
```

Then `f_i(m) ≡ 0 (mod n_i)` for each `i`. By CRT we build a single polynomial

```
f(x) ≡ 0 (mod N),   where N = Π n_i
```

`deg(f) = 7` and `N` is ~7165 bits. The flag is ~50 bytes, so `m < 2^700`. Since `N^{1/7} ≈ 2^1023`, the small‑root condition holds. We can use univariate Coppersmith to recover `m`.

### Coppersmith (Howgrave‑Graham) setup
Let `f(x)` be monic. Build the lattice from polynomials:

```
x^j * f(x)^i * N^{m-i}
```

for `i = 0..m-1`, `j = 0..d-1`, plus `x^j * f(x)^m` for `j = 0..t-1`.

We use:

- degree `d = 7`
- bound `X = 2^700`
- `m = 2`, `t = d`

Run LLL to find a short vector that corresponds to a polynomial `h(x)` with the same small root in `|x| < X` over the integers.

### Root extraction
`h(x)` is not easy to factor over `Z`, but we only need the small integer root. We:

1) Factor `h(x)` modulo many primes `p` (using `sympy` in finite fields).
2) Collect linear roots `r (mod p)`.
3) CRT‑lift these roots until the modulus exceeds `X`.
4) Verify the candidate by checking `f(m) ≡ 0 (mod N)` and decode.

---

## Solver Script (Python)

Save as `solve.py` and run with Python 3. It needs `fpylll`, `cysignals`, and `sympy`:

```
python3 -m venv /tmp/venv
/tmp/venv/bin/pip install fpylll cysignals sympy
/tmp/venv/bin/python solve.py
```

```python
#!/usr/bin/env python3
import ast
import math
from fpylll import IntegerMatrix, LLL
import sympy as sp
from sympy.ntheory import nextprime
from sympy.ntheory.modular import crt

# ---------- polynomial helpers ----------

def poly_add(p, q, mod=None):
    n = max(len(p), len(q))
    res = [0] * n
    for i in range(n):
        res[i] = (p[i] if i < len(p) else 0) + (q[i] if i < len(q) else 0)
        if mod:
            res[i] %= mod
    return res


def poly_mul(p, q, mod=None):
    res = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        for j, b in enumerate(q):
            res[i + j] += a * b
    if mod:
        res = [x % mod for x in res]
    return res


def poly_pow(p, exp, mod=None):
    res = [1]
    base = p
    e = exp
    while e > 0:
        if e & 1:
            res = poly_mul(res, base, mod)
        base = poly_mul(base, base, mod)
        e >>= 1
    return res


def poly_eval(p, x):
    res = 0
    for coeff in reversed(p):
        res = res * x + coeff
    return res


# ---------- build f(x) mod N ----------

def build_coeffs(rounds=7):
    k = 2 ** 1024
    a, b, c, d = 1 * k, 3 * k, 3 * k, 7 * k
    for _ in range(rounds):
        yield (a, b, c, d)
        a += 2 ** 1024
        b += 4 ** 1024
        c += 6 ** 1024
        d += 8 ** 1024


def build_polynomial(data, e=7):
    ns = [d["n"] for d in data]
    cs = [d["c"] for d in data]

    N = 1
    for n in ns:
        N *= n

    f = [0]
    coeff_list = list(build_coeffs(rounds=len(data)))

    for (n, ct), (a, b, c_coef, d) in zip(zip(ns, cs), coeff_list):
        # (a x + b)^e - ct * (c x + d)^e  (mod n)
        p1 = [b, a]
        p2 = [d, c_coef]
        p1e = poly_pow(p1, e, mod=n)
        p2e = poly_pow(p2, e, mod=n)
        term = [(p1e[i] - ct * p2e[i]) % n for i in range(len(p1e))]

        mult = N // n
        term = [(t * mult) % N for t in term]
        f = poly_add(f, term, mod=N)

    f = [x % N for x in f]
    lead = f[-1]
    if math.gcd(lead, N) != 1:
        raise ValueError("leading coeff not invertible mod N")

    inv = pow(lead, -1, N)
    f = [(c * inv) % N for c in f]  # make monic
    return f, N


# ---------- Coppersmith (univariate) ----------

def coppersmith_univariate(f, N, X, m=2, t=None):
    d = len(f) - 1
    if t is None:
        t = d

    # f^i
    f_pows = [[1]]
    for _ in range(1, m + 1):
        f_pows.append(poly_mul(f_pows[-1], f))

    polys = []
    for i in range(m):
        for j in range(d):
            p = [0] * j + f_pows[i][:]
            scale = pow(N, m - i)
            p = [c * scale for c in p]
            polys.append(p)

    for j in range(t):
        p = [0] * j + f_pows[m][:]
        polys.append(p)

    max_deg = max(len(p) - 1 for p in polys)
    rows = len(polys)
    cols = max_deg + 1

    M = IntegerMatrix(rows, cols)
    for r, p in enumerate(polys):
        for c, coeff in enumerate(p):
            M[r, c] = coeff * (X ** c)

    LLL.reduction(M)

    vec = [int(M[0, c]) for c in range(cols)]
    h = [vec[c] // (X ** c) for c in range(cols)]
    while h and h[-1] == 0:
        h.pop()

    return h


# ---------- root recovery by CRT lifting ----------

def roots_mod_prime(poly, p):
    poly_p = sp.Poly(poly, modulus=p)
    factors = poly_p.factor_list()[1]
    roots = []
    for fac, _ in factors:
        if fac.degree() == 1:
            a, b = fac.all_coeffs()
            a = int(a)
            b = int(b)
            root = (-b * pow(a, -1, p)) % p
            roots.append(root)
    return list(set(roots))


def recover_root(h, f, N, X):
    x = sp.symbols("x")
    poly = sp.Poly(sum(sp.Integer(h[i]) * x ** i for i in range(len(h))), x)

    cands = [0]
    mod = 1

    p = nextprime(2 ** 31)
    while True:
        rts = roots_mod_prime(poly, p)
        if 1 <= len(rts) <= 2:
            new_cands = []
            for c in cands:
                for r in rts:
                    res = crt([mod, p], [c, r])
                    if res[0] is None:
                        continue
                    new_cands.append(int(res[0]))
            mod *= p
            cands = list(set(new_cands))

            if mod > X:
                # reduce to [0, mod)
                cands = [c % mod for c in cands]
                cands = [c for c in cands if c < X]
                if len(cands) == 1:
                    break

        p = nextprime(p + 1000)

    # verify
    for r in cands:
        if r < X and poly_eval(f, r) % N == 0:
            return r
    return None


def main():
    data = ast.literal_eval(open("out.txt", "r").read())
    f, N = build_polynomial(data, e=7)

    # bound for the flag integer (safe upper bound)
    X = 2 ** 700

    h = coppersmith_univariate(f, N, X, m=2, t=7)
    root = recover_root(h, f, N, X)
    if root is None:
        print("no root found")
        return

    msg = root.to_bytes((root.bit_length() + 7) // 8, "big")
    print(msg)


if __name__ == "__main__":
    main()
```

---

## Notes
- The bound `X = 2^700` is safe for a typical CTF flag and well below `N^{1/7}`.
- If LLL fails on some systems, adjust `m` or `X` slightly (e.g., `m = 3` or `X = 2^600`).
- The CRT lifting step keeps the candidate set small by selecting primes where `h(x)` has only 1–2 roots modulo `p`.
