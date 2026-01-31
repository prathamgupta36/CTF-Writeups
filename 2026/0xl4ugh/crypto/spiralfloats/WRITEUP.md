# SpiralFloats Writeup

## Challenge summary

We are given a Sage script that:

- converts the flag bytes to an integer `flag`
- scales it to a real `x = flag * 10^{-flen}`
- applies a spiral transform 81 times
- prints the resulting real as a digit string (decimal point removed)
- masks some digits with `?`

The output provided:

```
?7086013?3756162?51694057?5285516?54803756?9202316?39221780?4895755?50591029
```

We need to recover the flag.

## Observations

From `prob.sage`:

```
flag = bytes_to_long(b'0xL4ugh{?????????????????????}')
flen = len(str(flag))
R = RealField(256)
phi = R((1 + sqrt(5)) / 2)
x = R(flag) * R(10) ** (-flen)
x = str(spiral(x, phi)).replace('.', '')
masked = mask(x)
```

Key facts:

- The flag length is fixed (30 bytes).
- The decimal string length `flen` is fixed (72 digits).
- The printed spiral value (after removing '.') is 76 digits long.
- The mask replaces `k = int(n * 0.13)` digits in fixed positions.
  For `n = 76`, `k = 9` positions are masked:
  `0, 8, 16, 25, 33, 42, 50, 59, 67`.
- Over the allowed flag range (prefix/suffix fixed), the first three masked
  positions (0, 8, 16) are constant. Only six digits are actually unknown.

That leaves only 10^6 candidates, but brute forcing flags directly is too slow
because `spiral()` is heavy. Instead, invert the spiral to recover `x` (and thus
the flag) from candidate digit strings.

## Inverting one spiral step

The forward step is:

```
x' = r * sqrt(x^2 + 1) + (1 - r) * (x + phi)
```

Let `a = r`, `b = 1 - r`, `A = 1 - 2r`. Rearranging:

```
y = a * sqrt(x^2 + 1) + b * x + b * phi
```

Set `y0 = y - b * phi`. Then:

```
y0 = a * sqrt(x^2 + 1) + b * x
```

Solving for `x` gives a quadratic with closed form:

```
x = (b * y0 - a * sqrt(y0^2 + A)) / A
```

The other root is not in our valid range; the above root recovers the original
`x` for all steps in this challenge (verified numerically).

Apply this inverse 81 times to recover the original `x` from the final spiral
value.

## Search strategy

1. Build the 76-digit string with known digits (from the mask).
2. Fill positions 0, 8, 16 with the constant digits from the minimum possible
   flag (all unknown bytes = 0x00). Only 6 positions remain unknown.
3. Enumerate all 10^6 combinations for these 6 digits:
   - Convert the 76-digit candidate to a real `y`.
   - Invert the spiral to recover `x`.
   - Recover integer `flag` from `x * 10^72` and round to nearest.
   - Filter by prefix/suffix and verify the mask.

This yields 41 valid byte strings. Only one is fully printable ASCII, which is
the expected CTF flag.

## Final flag

```
0xL4ugh{B1naryS3archM0not0n1c}
```

## Reference solver (Python)

This script is a standalone solver using `gmpy2` for 256-bit precision:

```python
#!/usr/bin/env python3
import gmpy2
from gmpy2 import mpfr
from Crypto.Util.number import bytes_to_long, long_to_bytes

ctx = gmpy2.get_context()
ctx.precision = 256

phi = (mpfr(1) + gmpy2.sqrt(mpfr(5))) / 2
iterations = 81
r_values = [mpfr(i) / mpfr(iterations) for i in range(iterations)]
coeffs = [(r, 1 - r, 1 - 2 * r) for r in r_values]
coeffs_rev = list(reversed(coeffs))

pow10_72 = mpfr(10) ** 72
pow10_74 = mpfr(10) ** (-74)
pow10_neg72 = mpfr(10) ** (-72)

def spiral_forward(x):
    for r, b, _A in coeffs:
        x = r * gmpy2.sqrt(x * x + 1) + b * (x + phi)
    return x

def s_for_N(N):
    x = mpfr(N) * pow10_neg72
    y = spiral_forward(x)
    return format(y, ".76g").replace(".", "")

def inverse_spiral(y):
    x = y
    for a, b, A in coeffs_rev:
        y0 = x - b * phi
        x = (b * y0 - a * gmpy2.sqrt(y0 * y0 + A)) / A
    return x

prefix = b"0xL4ugh{"
suffix = b"}"
unknown_len = 21
min_bytes = prefix + b"\x00" * unknown_len + suffix
max_bytes = prefix + b"\xff" * unknown_len + suffix
min_N = bytes_to_long(min_bytes)
max_N = bytes_to_long(max_bytes)

mask = "?7086013?3756162?51694057?5285516?54803756?9202316?39221780?4895755?50591029"

# Fill fixed digits at positions 0, 8, 16
min_digits = s_for_N(min_N)
mask_list = list(mask)
for pos in (0, 8, 16):
    mask_list[pos] = min_digits[pos]
filled_mask = "".join(mask_list)

unknown_positions = [i for i, ch in enumerate(filled_mask) if ch == "?"]

base_digits = "".join("0" if ch == "?" else ch for ch in filled_mask)
base_int = int(base_digits)
weights = [10 ** (75 - pos) for pos in unknown_positions]

solutions = []
for d0 in range(10):
    add0 = d0 * weights[0]
    for d1 in range(10):
        add1 = add0 + d1 * weights[1]
        for d2 in range(10):
            add2 = add1 + d2 * weights[2]
            for d3 in range(10):
                add3 = add2 + d3 * weights[3]
                for d4 in range(10):
                    add4 = add3 + d4 * weights[4]
                    for d5 in range(10):
                        Y_int = base_int + add4 + d5 * weights[5]
                        y = mpfr(Y_int) * pow10_74
                        x = inverse_spiral(y)
                        N = int(gmpy2.floor(x * pow10_72 + mpfr("0.5")))
                        if N < min_N or N > max_N:
                            continue
                        b = long_to_bytes(N)
                        if not (b.startswith(prefix) and b.endswith(suffix)):
                            continue
                        s = s_for_N(N)
                        if len(s) != 76:
                            continue
                        ok = True
                        for i, ch in enumerate(mask):
                            if ch != "?" and s[i] != ch:
                                ok = False
                                break
                        if ok:
                            solutions.append(b)

print("solutions", len(solutions))
for b in solutions:
    if all(32 <= c < 127 for c in b):
        print("flag", b.decode())
```

