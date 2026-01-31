# Cognitive Reminder Call — Writeup

## TL;DR

The service “authenticates” messages with a CRC32‐based MAC:

```
tag = CRC32( key || nonce || message )
```

CRC32 is linear. From any one valid `(nonce, message, tag)` you can recover the internal CRC state after processing the secret key (i.e., `CRC32(key)`), which lets you forge valid tags for any future `(nonce, message)`.

The server also “remembers” the key only through four CRC32 values of its four parts. Because CRC32 is easy to collide, you can fabricate your own four byte strings whose individual CRC32s equal those four numbers. The server then derives the AES key from the parts you supplied and encrypts the reward with that key—so you can decrypt the reward locally.

---

## Challenge Flow (Observed)

1. Banner shows a ciphertext:
   `Here is the flag: <IV||CT hex>`
   followed by an authenticated note:
   `Note: ... tag is <tag1> with nonce <nonce1>.`
2. The server prints 4 integers: `[c1, c2, c3, c4]`, claiming they’re “cognitive reminders” of the key (i.e., `CRC32(part_i)`).
3. It asks you to supply `Part 1..4 (hex)`, then demands:

   * `Please provide your nonce (hex):`
   * `Please provide the tag of the concatenation of the nonce and the 4 parts (hex):`
4. On success it prints:
   `Thanks for reminding me! Here is a reward: <IV||CT hex>`
   …along with an authenticated note.

---

## Vulnerability 1 — CRC32 as a MAC

CRC32 is not a cryptographic MAC. Treated as a state machine over GF(2), the update

```
s’ = CRC32_update(s, data)
```

is affine in the 32-bit state `s`. The whole computation

```
tag = CRC32(message, CRC32(nonce, CRC32(key)))
```

is a composition of two affine maps applied to an unknown 32-bit vector `CRC32(key)`.

### Recovering `CRC32(key)` from one sample

Let:

* `N` = bytes of `nonce1`
* `M` = bytes of `message1`
* `T` = observed tag (32-bit)
* `sK` = unknown `CRC32(key)`

Define the affine operator for a byte string `X` as:

```
f_X(s) = A_X * s  ⊕  b_X     (over GF(2) on 32 bits)
```

`A_X, b_X` can be derived by calling the real CRC32 update on:

* initial state 0  → gives `b_X`
* each basis state `2^i` → columns of `A_X`

Then:

```
T = f_M( f_N(sK) ) = (A_M A_N) sK  ⊕  (A_M b_N ⊕ b_M)
```

The 32×32 matrix `A = A_M A_N` is invertible, so:

```
sK = A^{-1} ( T ⊕ (A_M b_N ⊕ b_M) )
```

This gives `CRC32(key)` exactly as the implementation uses it (no guessing about polynomials, reflect, or endianness).

> Practical note: some services MAC the line with or without the trailing newline. Test both variants against multiple “Note:” lines and choose the one that matches them all.

---

## Vulnerability 2 — “Cognitive reminders” are just CRC32s

The server only verifies `CRC32(part_i) == c_i`. For CRC32 you can efficiently find preimages:

* Fix a 4-byte prefix (e.g., `\x00\x00\x00\x00`),
* Solve for a 4-byte suffix `S` so that `CRC32(prefix || S) = target`.

Because the CRC update is affine in the initial state, this reduces to a 32×32 linear system over GF(2) (one per target). You get tiny 8-byte “parts” per reminder.

The server derives the AES key as:

```
key = SHA256(part1 || part2 || part3 || part4)
```

and uses it to encrypt the reward. Since you chose the parts, you know the key.

---

## Exploit Plan (Step-by-Step)

1. Parse the transcript until “Part 1 (hex):”. Collect:

   * the four integers `[c1..c4]`,
   * at least one `(nonce, message, tag)` from a “Note:” line (usually the line right after “Here is the flag: …”).
2. Recover `sK = CRC32(key)` with the linear-algebra method above (try both “include newline” and “no newline”, pick the one that validates across notes).
3. Build four parts with `CRC32(part_i)=c_i`. A convenient construction is 8 bytes per part: `00000000 || suffix_i`.
4. Send the four parts when prompted.
5. Nonce + Tag:

   * Choose any fresh 4-byte nonce `n`.
   * The service asks for the tag of the *concatenation of the nonce and the 4 parts*. Two common shapes exist:

     * `payload = nonce || part1 || part2 || part3 || part4`
     * `payload = part1 || part2 || part3 || part4` (despite the wording)
   * Compute:

     ```
     tag = CRC32(payload, CRC32(nonce, sK))
     ```

     Try the first shape; if rejected, try the second.
6. On success, the server prints the reward ciphertext (`IV || CT`).
   Derive `key = SHA256(part1||part2||part3||part4)` and AES-CBC decrypt to recover the final flag.

---

## Pseudocode Snippets

### Recover `CRC32(key)` from one sample

```python
def crc_update(state, data):  # uses binascii.crc32
    return binascii.crc32(data, state) & 0xffffffff

def build_affine(data):
    b = crc_update(0, data)
    cols = []
    for i in range(32):
        cols.append(crc_update(1<<i, data) ^ b)  # column i of A
    return (cols, b)

def invert_cols(cols):  # 32x32 GF(2) Gauss-Jordan on column form
    ...

def compose(op2, op1):  # (A2,b2)∘(A1,b1) = (A2A1, A2 b1 ⊕ b2)
    cols2, b2 = op2
    cols1, b1 = op1
    A = [mat_mul_vec(cols2, cols1[i]) for i in range(32)]
    b = mat_mul_vec(cols2, b1) ^ b2
    return (A, b)

# given (nonce, msg, tag):
A_N, b_N = build_affine(nonce)
A_M, b_M = build_affine(msg)
A, b = compose((A_M, b_M), (A_N, b_N))
Ainv = invert_cols(A)
sK = mat_mul_vec(Ainv, tag ^ b)
```

### Make bytes with a chosen CRC32

```python
def make_part_with_crc32(target):
    prefix = b"\x00"*4
    init   = binascii.crc32(prefix) & 0xffffffff
    const  = crc_update(init, b"\x00\x00\x00\x00")
    cols   = [(crc_update(init, (1<<i).to_bytes(4, "little")) ^ const) for i in range(32)]
    inv    = invert_cols(cols)
    x      = mat_mul_vec(inv, target ^ const)
    return prefix + x.to_bytes(4, "little")
```

### Forge the final tag

```python
payload = nonce + part1 + part2 + part3 + part4    # or just the parts
tag = crc_update(crc_update(sK, nonce), payload)
```

---

## Gotchas & Debugging

* Newline ambiguity: The MAC’ed `message` line might include the trailing `\n`. Recover `sK` twice (with and without `\n`) and pick the one that validates across other “Note:” lines (tags match exactly).
* Payload shape ambiguity: Despite the prompt’s wording, some instances expect the MAC over just `parts` (not `nonce||parts`). Try both—automate the fallback.
* Endianness/reflect: Using the platform’s `binascii.crc32` consistently for both recovery and forging avoids all polynomial/reflect pitfalls.

---

## Mitigations

* Never use CRC32 (or any linear checksum) as a MAC.
  Use a real MAC (e.g., HMAC-SHA-256) or an AEAD mode (AES-GCM, ChaCha20-Poly1305).
* Don’t authenticate “ad-hoc formatted strings.” Define and document your exact byte layout, including line endings, and use a canonical serialization.

---

## Takeaways

* CRC32 is linear; given one authenticated transcript line you can recover the secret’s CRC state and forge tags.
* “Remembering” secrets by their CRC32 fingerprints is meaningless—attackers can craft collisions at will.
* The challenge cleverly combines both mistakes so the attacker ends up choosing the AES key used to wrap the reward.

