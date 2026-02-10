# Spreading Secrets (crypto/spreading-secrets)

## Summary
The share generation uses a polynomial whose coefficients are produced by iterating a cubic RNG with seed equal to the secret. Because the coefficients are deterministic iterates of that seed, the single published share is already a fixed polynomial equation in the secret. Solving that equation over the prime field reveals the flag.

## Challenge recap
The challenge code:
- Picks a 512-bit prime `p`.
- Defines an RNG with state `s` and update
  
  `f(s) = a*s^3 + b*s^2 + c*s + d (mod p)`.
- Builds a degree-9 Shamir polynomial where:
  - constant term is the secret `s`,
  - remaining coefficients are `f(s), f(f(s)), ..., f^8(s)`.
- Publishes only one share `(x=1, y)`.

Because `x=1`, the share is simply the sum of all coefficients:

`y = s + f(s) + f^2(s) + ... + f^9(s) (mod p)`.

So the secret is a root of a single polynomial equation of degree `3^9 = 19683` over `GF(p)`.

## Solution idea
Let `f(x)` be the cubic RNG update. Define:

`G(x) = (x + f(x) + f^2(x) + ... + f^9(x)) - y  (mod p)`.

Then the true secret `s` is a root of `G(x)` in `GF(p)`.

We compute `G(x)` by repeated composition and summation, then find its roots mod `p`. Among the roots, the one that decodes as ASCII contains the flag.

## Implementation (solver)
Below is a minimal solver using `python-flint` for fast polynomial arithmetic and root finding.

```python
from flint import fmpz_mod_poly_ctx

p = 12670098302188507742440574100120556372985016944156009521523684257469947870807586552014769435979834701674318132454810503226645543995288281801918123674138911

a = 4378187236568178488156374902954033554168817612809876836185687985356955098509507459200406211027348332345207938363733672019865513005277165462577884966531159
b = 5998166089683146776473147900393246465728273146407202321254637450343601143170006002385750343013383427197663710513197549189847700541599566914287390375415919
c = 4686793799228153029935979752698557491405526130735717565192889910432631294797555886472384740255952748527852713105925980690986384345817550367242929172758571
d = 4434206240071905077800829033789797199713643458206586525895301388157719638163994101476076768832337473337639479654350629169805328840025579672685071683035027

y = 6435837956013280115905597517488571345655611296436677708042037032302040770233786701092776352064370211838708484430835996068916818951183247574887417224511655

R = fmpz_mod_poly_ctx(p)
x = R.gen()

h = x
S = R(0)
for i in range(10):
    S = S + h
    if i != 9:
        h = a*h**3 + b*h**2 + c*h + d

G = S - y
roots = G.roots(multiplicities=False)

for r in roots:
    s = int(r)
    bts = s.to_bytes((s.bit_length()+7)//8, 'big')
    if b"lactf{" in bts:
        print(bts.decode())
```

## Result
The valid root decodes to the flag:

`lactf{d0nt_d3r1v3_th3_wh0l3_p0lyn0m14l_fr0m_th3_s3cr3t_t00!!!}`

## Notes
- Only one share is enough because the coefficients are not random; they are deterministic iterates of the secret.
- The polynomial degree grows as `3^k` due to cubic composition, but `python-flint` handles degree ~20k comfortably on a modern machine.
