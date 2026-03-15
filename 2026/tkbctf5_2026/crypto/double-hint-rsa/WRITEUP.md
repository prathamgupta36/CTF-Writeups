# Double Hint RSA

- Status: solved locally
- Flag: `tkbctf{I_still_really_want_to_provide_not_only_n%m_but_also_n%(m+e)}`

## Challenge

The generator is:

```python
e = 11
flag = ...
assert len(flag) == 60
m = bytes_to_long(flag)
p = getPrime(512)
q = getPrime(512)
n = p * q
c = pow(m, e, n)
hint1 = n % m
hint2 = n % (m + e)
```

We are given `n`, `e`, `c`, `hint1`, and `hint2`.

At first glance this looks similar to the earlier `single-hint-rsa` challenge, except now we leak two nearby remainders:

```text
n mod m
n mod (m + e)
```

The plaintext is 60 bytes, so `m` is about 480 bits, while `n` is 1024 bits. That means:

```text
k = floor(n / m)
```

is roughly 544 bits, and the difference between:

```text
floor(n / m) and floor(n / (m + e))
```

is much smaller. That small gap is the quantity we want to recover.

## Step 1: Introduce the quotient variables

Define:

```text
X = n - hint1 = k * m
Y = n - hint2 = l * (m + e)
```

for:

```text
k = floor(n / m)
l = floor(n / (m + e))
```

Now define the small difference:

```text
d = k - l
```

Since `m` and `m + e` are extremely close, `d` is small. In the recovered instance:

```text
d = 1768407027079372647298
```

which is only 71 bits.

## Step 2: Derive an exact quadratic relation

We have:

```text
Y = (k - d)(m + e)
```

and also:

```text
X = k m
```

Subtracting the hints gives:

```text
Delta = hint1 - hint2 = Y - X
```

Substitute `Y = (k - d)(m + e)` and `m = X / k`:

```text
Delta = (k - d)(X / k + e) - X
```

Multiply through by `k` and simplify:

```text
11 k^2 - (Delta + 11 d) k - d X = 0
```

So `k` and `d` satisfy an exact quadratic equation over the integers.

For this concrete instance, both `X` and `Delta` are divisible by `11`, so we can divide the whole relation by `11`.

Let:

```text
X1 = X / 11
Delta1 = Delta / 11
```

Then:

```text
k^2 - (Delta1 + d) k - d X1 = 0
```

This cleaner form is what the solver uses.

## Step 3: Reuse the RSA relation from the single-hint version

From:

```text
X = k m
```

we get:

```text
m = X / k
```

Plug this into RSA:

```text
c = m^11 mod n
```

which gives:

```text
c * k^11 = X^11 mod n
```

Since `X = n - hint1`, we have:

```text
X ≡ -hint1 mod n
```

so:

```text
c * k^11 + hint1^11 ≡ 0 mod n
```

Define:

```text
g(k) = c * k^11 + hint1^11
```

Then the real `k` is a root of `g(k)` modulo `n`.

## Step 4: Eliminate `k`

We now have two equations:

```text
g(k) = c * k^11 + hint1^11 ≡ 0 mod n
q(k, d) = k^2 - (Delta1 + d) k - d X1 = 0
```

The second is exact over the integers; the first is modulo `n`.

Take the resultant of `g` and `q` with respect to `k`:

```text
res(d) = resultant_k(g(k), q(k, d))
```

This removes `k` and leaves a univariate polynomial in `d` modulo `n`.

Important properties:

- `res(d)` has degree `11`
- the real root `d` is only about `71` bits
- `n` is 1024 bits

That is exactly the kind of setup where univariate Coppersmith applies.

## Step 5: Recover `d` with Coppersmith

Sage's built-in `small_roots()` did not recover the root reliably here, so the solver uses a manual univariate Coppersmith lattice:

```text
N^(m-i) * f(x)^i * x^j
```

for several lifting parameters `m`, followed by:

- coefficient embedding
- column scaling by the root bound
- LLL reduction
- integer root search on the reduced polynomials

This finds:

```text
d = 1768407027079372647298
```

## Step 6: Recover `k`, then `m`

Once `d` is known, solve the quadratic:

```text
k^2 - (Delta1 + d) k - d X1 = 0
```

using the discriminant:

```text
disc = (Delta1 + d)^2 + 4 d X1
```

Then:

```text
k = ((Delta1 + d) ± sqrt(disc)) / 2
```

For the valid root:

```text
m = X / k
```

and we verify:

```text
Y % (m + e) == 0
pow(m, e, n) == c
```

Converting `m` back to 60 bytes gives:

```text
I_still_really_want_to_provide_not_only_n%m_but_also_n%(m+e)
```

so the flag is:

```text
tkbctf{I_still_really_want_to_provide_not_only_n%m_but_also_n%(m+e)}
```

## Solver

The full solver is in `solve.sage`. The core steps are:

1. Build the quadratic relation in `k` and `d`.
2. Take the resultant to get a degree-11 polynomial in `d`.
3. Recover the small root `d` with a manual univariate Coppersmith lattice.
4. Solve for `k`.
5. Recover `m = X / k`.
6. Verify and decode the plaintext.

## Reproduction

Run:

```bash
env DOT_SAGE=/tmp/.sage /home/al/.local/miniforge3/bin/conda run -n sage sage solve.sage
```

Expected output:

```text
d = 1768407027079372647298
flag = tkbctf{I_still_really_want_to_provide_not_only_n%m_but_also_n%(m+e)}
```
