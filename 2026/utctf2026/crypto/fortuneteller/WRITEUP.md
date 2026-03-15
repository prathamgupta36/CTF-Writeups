# Fortune Teller Writeup

## Challenge Info

- Name: `Fortune Teller`
- Category: `Crypto`
- Points: `673`
- Author: `Garv (@GarvK07 on discord)`

Challenge text:

> Our security team built a "cryptographically secure" random number generator. The lead engineer assured us it was basically AES. He has since been let go.

Provided data from [`lcg.txt`](./lcg.txt):

```text
We're using a Linear Congruential Generator (LCG) defined as:

  x_(n+1) = (a * x_n + c) % m

where m = 4294967296 (2^32), and a and c are secret.

We intercepted the first 4 outputs of the generator:

  output_1 = 4176616824
  output_2 = 2681459949
  output_3 = 1541137174
  output_4 = 3272915523

The flag was encrypted by XORing it with output_5 (used as a 4-byte repeating key).

  ciphertext (hex) = 3cff226828ec3f743bb820352aff1b7021b81b623cff31767ad428672ef6
```

## Initial Observation

This is not "basically AES". It is an LCG:

```text
x_(n+1) = (a * x_n + c) mod m
```

An LCG is completely predictable once enough consecutive outputs are known. Here we are given four consecutive outputs, which is more than enough to recover the hidden parameters `a` and `c`, then compute `output_5`.

Since the flag was XORed with `output_5` as a repeating 4-byte key, recovering that next output immediately gives the key stream.

## Recovering the Multiplier

Let:

```text
x1 = 4176616824
x2 = 2681459949
x3 = 1541137174
x4 = 3272915523
m  = 2^32 = 4294967296
```

From the recurrence:

```text
x2 = a*x1 + c mod m
x3 = a*x2 + c mod m
```

Subtract the equations:

```text
x3 - x2 = a * (x2 - x1) mod m
```

So:

```text
a = (x3 - x2) * (x2 - x1)^(-1) mod m
```

Compute the differences:

```text
x2 - x1 mod m = 2799810421
x3 - x2 mod m = 3154644521
```

Because `gcd(2799810421, 2^32) = 1`, the modular inverse exists. Therefore:

```text
a = 3154644521 * 2799810421^(-1) mod 2^32
  = 3355924837
```

## Recovering the Increment

Now substitute back into:

```text
x2 = a*x1 + c mod m
```

So:

```text
c = x2 - a*x1 mod m
  = 2915531925
```

We can verify:

```text
(a*x2 + c) mod m = x3
(a*x3 + c) mod m = x4
```

which holds.

## Predicting the Next Output

Now compute:

```text
x5 = a*x4 + c mod m
   = 1233863684
   = 0x498b4404
```

The challenge says `output_5` was used as a 4-byte repeating XOR key. Using the bytes of `0x498b4404` in big-endian order gives:

```text
49 8b 44 04
```

## Decrypting the Ciphertext

Ciphertext:

```text
3cff226828ec3f743bb820352aff1b7021b81b623cff31767ad428672ef6
```

XOR with the repeating key `49 8b 44 04`:

```text
3c ff 22 68 28 ec 3f 74 ...
49 8b 44 04 49 8b 44 04 ...
--------------------------------
75 74 66 6c 61 67 7b 70 ...
```

This decodes to:

```text
utflag{pr3d1ct_th3_futur3_lcg}
```

## Solver

A reproducible solver is included in [`solve.py`](./solve.py).

Run:

```bash
python3 solve.py
```

Expected output:

```text
a = 3355924837
c = 2915531925
output_5 = 1233863684 (0x498b4404)
selected endian = big
key = 498b4404
utflag{pr3d1ct_th3_futur3_lcg}
```

## Why This Works

The core weakness is that an LCG is linear and fully predictable. Once several consecutive outputs are exposed, the hidden parameters can be solved algebraically. This makes it unsuitable for cryptographic use.

The challenge author's joke is the entire point: calling an LCG "basically AES" is catastrophically wrong.

## Flag

```text
utflag{pr3d1ct_th3_futur3_lcg}
```
