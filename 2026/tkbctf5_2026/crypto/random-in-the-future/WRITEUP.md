# Random In The Future

- Status: solved
- Flag: `tkbctf{https://www.tsukuba.ac.jp/en/about/public-branding/branding}`

## Challenge

The challenge code is short:

```python
flag = os.environ.get("FLAG", "tkbctf{dummy}")
a = b = 1
for _ in range(100):
    print(random.getrandbits(b))
    a, b = b, a + b
print(AES.new(random.randbytes(16), AES.MODE_ECB).encrypt(pad(flag.encode(), 16)).hex())
```

The key points are:

1. The PRNG is Python's `random`, i.e. MT19937.
2. The bit lengths are Fibonacci numbers.
3. We only see the first 20 outputs. The remaining 80 are censored.
4. After all 100 `getrandbits()` calls, the script uses the same PRNG again to generate the AES key.

The joke in the description is that "future CPython" can handle absurdly large integers, so the later Fibonacci-sized calls are enormous. The real problem is recovering the MT state and then jumping an absurd distance forward.

## Observation 1: `getrandbits()` leaks raw MT words

For Python's `random`, `getrandbits(k)` is built from `ceil(k / 32)` MT outputs. The words are concatenated little-endian by 32-bit chunks, and if `k` is not a multiple of 32 then the last chunk is truncated to its top `k mod 32` bits.

So each printed integer is just a pile of MT19937 32-bit outputs.

For the first 20 Fibonacci bit-lengths:

```text
1, 2, 3, 5, 8, 13, 21, 34, ..., 10946
```

the total number of consumed 32-bit MT words is:

```text
sum(ceil(F_i / 32), i = 1..20) = 907
```

That is already more than enough to cover a full MT state of 624 words.

## Observation 2: the transcript gives 624 consecutive words, but some are partial

Expanding the first 20 outputs into 32-bit chunks gives 907 chunks total.

- Chunks `0..623` belong to one MT state.
- Chunks `624..906` are the first 283 outputs of the next state after one twist.

Among the first 624 chunks, most are full 32-bit words, but 19 of them are truncated final chunks from `getrandbits(k)` calls. Altogether this leaves:

```text
339 unknown low bits
```

So we do not know the first MT state exactly, but we know it up to 339 unknown bits.

## Observation 3: MT19937 is linear over GF(2)

Both of these operations are linear over GF(2):

- untempering a 32-bit output back to a state word
- twisting one 624-word state into the next

That means we can treat every unknown bit in the partial chunks as a variable, then:

1. symbolically untemper the first 624 observed outputs,
2. symbolically apply one twist,
3. symbolically temper the first 283 outputs of the next state,
4. constrain them using the 283 observed chunks `624..906`.

This gives a linear system over GF(2).

For this instance:

- unknown variables: `339`
- rank from the second-state constraints: `298`
- remaining nullity: `41`

So the transcript narrows the first MT state down to an affine space of dimension 41.

That is already small, but we still cannot brute-force all `2^41` possibilities directly.

## Observation 4: iterating to the AES key is impossible

The key is produced after **100** Fibonacci-sized `getrandbits()` calls.

The number of consumed 32-bit MT outputs before `randbytes(16)` is:

```text
W = sum(ceil(F_i / 32), i = 1..100)
  = 46891266756465502660
```

After recovering the first full state, we still need the MT words near index:

```text
W - 624 = 46891266756465502036
```

Clearly we cannot step the generator forward one output at a time.

## Observation 5: each MT output bit follows a degree-19937 linear recurrence

MT19937 is an F2-linear generator. Therefore, for any fixed output bit position, the infinite output stream satisfies one linear recurrence over GF(2) of degree 19937.

We do not need to derive that polynomial by hand. We can recover it from any sample MT stream with Berlekamp-Massey. I used 45000 sample bits from a local MT instance and obtained the expected degree-19937 characteristic polynomial.

Once we have the characteristic polynomial `c(x)`, a far-future bit at offset `n` can be written as a linear combination of the first 19937 bits:

```text
x^n mod c(x)
```

So for each of the four 32-bit words that make up the future 128-bit AES key, we can compute the exact XOR mask over the first 19937 observed bits of a known state, without iterating `10^19` steps.

This is the crucial skip-ahead trick.

## Observation 6: only a small part of the 41-dimensional ambiguity survives to the key

From the 41 nullspace basis vectors, I evaluated how each one changes the future 128-bit key.

Result:

- 30 basis directions do not affect the key at all
- only 11 basis directions matter

So instead of `2^41` candidates, we only need to try:

```text
2^11 = 2048
```

For each candidate:

1. build the corresponding AES key,
2. decrypt the ciphertext,
3. check PKCS#7 padding,
4. check that the plaintext matches `tkbctf{...}`.

That immediately yields the flag.

## Reproduction

The solver is in [solve.py](/home/al/Downloads/CTF/tkbctf5_2026/crypto/random-in-the-future/solve.py).

Run:

```bash
python solve.py
```

It prints:

```text
tkbctf{https://www.tsukuba.ac.jp/en/about/public-branding/branding}
```

## Solution summary

The challenge looks like an "impossible skip into the future" problem, but the real structure is:

1. the first 20 outputs already reveal 907 underlying MT words,
2. that is enough to recover the MT state up to a small affine subspace,
3. MT is linear, so the huge jump can be handled with recurrence arithmetic instead of simulation,
4. only 11 free directions influence the final AES key,
5. brute-force those 2048 candidates and decrypt.

So the solve is a combination of:

- exact modeling of Python `getrandbits()`,
- symbolic MT state recovery over GF(2),
- Berlekamp-Massey on the MT output bitstream,
- and a tiny final brute-force.
