# Leaked d - Crypto Challenge Writeup

## Challenge

> Someone leaked my d, surely generating a new key pair is safe enough.

We are given:

```
n1 = 144193923737869044259998596038292537217126517072587407189785154961344425600188709243733103713567903690926695626210849582322575275021963176688615503362430255878068025864333805901831356111202249176714839010151878345993886718863579928588098080351940561045688931786378656665718140998014299097023143181095121810219

e1 = 65537

d1 = 12574092103116126584156918631595005114605155027996964036950457918490065036621732354668884564796078087090438462300608898225025828108557296714458055780952572974382089675780912070693778415852291145766476219909978391880801604060224785419022793121117332853938170749724540897211958251465747669952580590146500249193

e2 = 6767671

c  = 31703515320997441500407462163885912085193988887521686491271883832485018463764003313655377418478488372329742364292629844576532415828605994734718987367062694340608380583593689052813716395874850039382743513756381017287371000882358341440383454299152364807346068866304481227367259672607408256375720022838698292966
````

Goal: recover the plaintext / flag.

---

## High-level idea

* We're given a full RSA key: `(n1, e1, d1)`.
* Then the challenge author "changes" the key by only changing the public exponent to `e2 = 6767671`, **reusing the same modulus** `n1`.
* The ciphertext `c` is clearly encrypted with the *new* public key `(n1, e2)`, not with `(n1, e1)`.

The claim in the flavour text is:

> "Someone leaked my d, surely generating a new key pair is safe enough."

They *didn't* generate a new key pair.
They only changed `e` and reused the same `n`. If `d1` is leaked, we can factor `n1`, recover φ(n1), and then derive the new private exponent for `e2`.

---

## Background: leaking `d` breaks RSA

In RSA we have:

* Modulus: `n = p · q`
* Public exponent: `e`
* Private exponent: `d`
* Euler's totient: `φ(n) = (p − 1)(q − 1)`

They satisfy:

$$
e \cdot d \equiv 1 \pmod{\varphi(n)}
$$

So there exists some integer `k` such that:

$$
e \cdot d - 1 = k \cdot \varphi(n)
$$

This means `k = e·d − 1` is a **multiple** of φ(n). Using this property, there's a well-known method to factor `n` given `(n, e, d)`.

---

## Step 1 - From leaked `d1` to factoring `n1`

Let:

```text
k = e1 * d1 - 1
```

This `k` is even (since φ(n) is even for RSA-sized n), so we write:

$$
k = 2^r \cdot t
$$

with `t` odd (repeatedly divide by 2 until it's odd).

Then we use a procedure very similar to the inner loop of the Miller-Rabin primality test:

1. Pick random `g` with `2 ≤ g ≤ n1 − 2`.
2. Compute `x = g^t mod n1`.
3. If `x == 1` or `x == n1 − 1`, try another `g`.
4. Otherwise, repeatedly square:

   * For `i` from `1` to `r`:

     * `y = x² mod n1`
     * If `y == 1`, then a non-trivial factor of `n1` is:
       $$
       p = \gcd(x - 1, n1)
       $$
       and `q = n1 / p`.
     * Set `x = y` and continue.

Because `k` is a multiple of φ(n1), this process is guaranteed (with high probability over random `g`) to eventually find a non-trivial factor.

Running this on the given parameters yields primes `p` and `q` such that:

```
n1 = p * q
```

Now we can compute:

```
phi = (p - 1) * (q - 1)
```

---

## Step 2 - Build the *new* private key for `e2`

The challenge says the author changed the key by choosing a new public exponent:

```
e2 = 6767671
```

but kept the same modulus `n1`.

Once we know φ(n1), the correct private exponent corresponding to `e2` is the modular inverse:

$$
d_2 \equiv e_2^{-1} \pmod{\varphi(n_1)}
$$

In code:

```python
d2 = pow(e2, -1, phi)  # Python 3.8+ syntax
```

This gives the private key `(n1, d2)` for the "new" public key `(n1, e2)`.

---

## Step 3 - Decrypt the ciphertext

Now we can decrypt:

$$
m \equiv c^{d_2} \pmod{n_1}
$$

In code:

```python
m = pow(c, d2, n1)
```

Then convert the resulting integer `m` to bytes and decode it as ASCII/UTF-8. That should give the flag.

---

## Full solve script (Python)

Here is a complete Python script that performs the attack end-to-end:

```python
from math import gcd
import random

n1 = 144193923737869044259998596038292537217126517072587407189785154961344425600188709243733103713567903690926695626210849582322575275021963176688615503362430255878068025864333805901831356111202249176714839010151878345993886718863579928588098080351940561045688931786378656665718140998014299097023143181095121810219

e1 = 65537

d1 = 12574092103116126584156918631595005114605155027996964036950457918490065036621732354668884564796078087090438462300608898225025828108557296714458055780952572974382089675780912070693778415852291145766476219909978391880801604060224785419022793121117332853938170749724540897211958251465747669952580590146500249193

e2 = 6767671

c = 31703515320997441500407462163885912085193988887521686491271883832485018463764003313655377418478488372329742364292629844576532415828605994734718987367062694340608380583593689052813716395874850039382743513756381017287371000882358341440383454299152364807346068866304481227367259672607408256375720022838698292966


def factor_from_leaked_d(n, e, d):
    """
    Factor n given a valid RSA private exponent d for public exponent e.
    Based on the standard attack using k = e*d - 1.
    """
    k = e * d - 1

    # write k = 2^r * t with t odd
    r = 0
    t = k
    while t % 2 == 0:
        t //= 2
        r += 1

    while True:
        g = random.randrange(2, n - 1)
        x = pow(g, t, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r):
            y = pow(x, 2, n)
            if y == 1:
                p = gcd(x - 1, n)
                if 1 < p < n:
                    q = n // p
                    return p, q
            x = y


# Step 1: factor n1
p, q = factor_from_leaked_d(n1, e1, d1)
assert p * q == n1

phi = (p - 1) * (q - 1)

# Step 2: compute d2 such that e2 * d2 ≡ 1 (mod phi)
def invmod(a, m):
    # extended Euclidean algorithm
    def egcd(x, y):
        if y == 0:
            return x, 1, 0
        g, s, t = egcd(y, x % y)
        return g, t, s - (x // y) * t

    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

d2 = invmod(e2, phi)

# Step 3: decrypt
m = pow(c, d2, n1)

# convert integer -> bytes
m_hex = hex(m)[2:]
if len(m_hex) % 2 == 1:
    m_hex = "0" + m_hex

plaintext = bytes.fromhex(m_hex)
print(plaintext)
```

Running this script prints the flag:

```
b'uoftctf{1_5h0u1dv3_ju57_ch4ng3d_th3_wh013_th1ng_1n5734d}'
```

---

## Takeaways

* **Leaking `d` completely breaks RSA.** Once the private exponent is known, the modulus can be factored in polynomial time.
* **Reusing the modulus `n` is dangerous.** Even if you pick a new public exponent `e2`, anyone who saw the old `d1` can:

  1. Factor `n`,
  2. Recompute φ(n),
  3. Derive the new private exponent `d2` for any new `e2`.
* A "new key pair" means **new (p, q)** and hence a new modulus `n`, not just changing `e`.

The challenge nicely illustrates why "just changing the exponent" is not enough once a private key has been compromised.