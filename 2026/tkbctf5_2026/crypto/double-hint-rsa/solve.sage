from math import gcd


n = 128699332750466917915234201683912530202344945513860856992865065133609055191232376715443146804309569036866830157522024110632642284724524859157296347234634747117764325677476263794931185515847716344473460460601920709656473697942719828622364501719928002712423694856785503668586464351178396589377492753508649311183
e = 11
c = 15506368997613691820068946312088316626538964472342488351443154876590126131639836902053961983839820990374104794875775323501975577347399870864133035669049310238108705352129432720329474953334389450944276060779768610437625102548074186021080090498988846142210131325541028112193547508541558028088192756141643243759
h1 = 537390599735844350892866232122316356354946429070305822911872260054257238721388000730211367300646400567524724625348447949038405065299459300709448
h2 = 11507042873576162799126455943988609977365689215981970602803804902458228504574905463310779753839575560424560376158416280231159321883329555071915

X = n - h1
Y = n - h2
Delta = h1 - h2

assert X % e == 0
assert Delta % e == 0

X1 = X // e
Delta1 = Delta // e


def coppersmith_univariate(poly_mod_n, bound, mmax=6):
    poly_z = poly_mod_n.change_ring(ZZ)
    x = poly_z.parent().gen()
    deg = poly_z.degree()

    for mparam in range(1, mmax + 1):
        shifts = []
        for i in range(mparam + 1):
            base = (n ** (mparam - i)) * (poly_z ** i)
            for j in range(deg):
                shifts.append((x ** j) * base)

        maxdeg = max(p.degree() for p in shifts)
        monomials = [x ** k for k in range(maxdeg + 1)]

        basis = Matrix(ZZ, len(shifts), len(monomials))
        for row_idx, poly in enumerate(shifts):
            for col_idx, monomial in enumerate(monomials):
                basis[row_idx, col_idx] = poly.monomial_coefficient(monomial)

        scales = [monomial(bound) for monomial in monomials]
        for col_idx, scale in enumerate(scales):
            basis.rescale_col(col_idx, scale)

        reduced = basis.LLL().change_ring(QQ)
        for col_idx, scale in enumerate(scales):
            reduced.rescale_col(col_idx, QQ(1) / scale)

        for row in reduced.rows():
            candidate_poly = sum(
                ZZ(row[i]) * monomials[i] for i in range(len(monomials)) if row[i]
            )
            if candidate_poly == 0:
                continue

            for root, _mult in candidate_poly.roots(ring=ZZ):
                if abs(root) >= bound:
                    continue
                if ZZ(poly_z(root)) % n == 0:
                    return ZZ(root)

    return None


# Let k = floor(n / m) and d = floor(n / m) - floor(n / (m + e)).
#
# From hint1:
#   X = k * m
# and from RSA:
#   c * k^e + h1^e == 0 (mod n)
#
# Since this instance also satisfies X % 11 == 0 and Delta % 11 == 0, the two
# hint equations combine into the exact quadratic
#   k^2 - (Delta1 + d) * k - d * X1 = 0
# with small d. Eliminating k gives a degree-11 polynomial in d modulo n.
P.<k, d> = PolynomialRing(ZZ)
g = c * k^e + h1^e
q = k^2 - (Delta1 + d) * k - d * X1
res = g.resultant(q, k).univariate_polynomial()

lead = ZZ(res.leading_coefficient())
assert gcd(lead, n) == 1

R.<x> = PolynomialRing(Zmod(n))
f = R(res) * inverse_mod(lead, n)
assert f.is_monic()

d_root = coppersmith_univariate(f, 2^75)
if d_root is None:
    raise SystemExit("failed to recover the quotient gap")

disc = (Delta1 + d_root) ^ 2 + 4 * d_root * X1
sqrt_disc = isqrt(disc)
assert sqrt_disc ^ 2 == disc

flag_bytes = None
for k_root in (
    (Delta1 + d_root + sqrt_disc) // 2,
    (Delta1 + d_root - sqrt_disc) // 2,
):
    if k_root <= 0 or X % k_root != 0:
        continue

    m = X // k_root
    if Y % (m + e) != 0:
        continue
    if pow(m, e, n) != c:
        continue

    flag_bytes = int(m).to_bytes(60, "big")
    break

if flag_bytes is None:
    raise SystemExit("failed to recover the plaintext")

print("d =", d_root)
print("flag = tkbctf{" + flag_bytes.decode() + "}")
