# LakeCTF 2025 – "Ez Part" Write-Up

## Challenge Overview
- **Category:** Crypto
- **Service:** `chall.polygl0ts.ch:6027`
- **Files Provided:** `chall.py`, `Dockerfile`, `DESCRIPTION.md`
- **Goal:** Authenticate as the pre-registered `admin` user to obtain the flag.

The service exposes a Flask API with three main endpoints:
1. `POST /create-account` – registers `username` with password-derived secret `x`.
2. `POST /prove-id` – checks a provided password against the stored secret and, if `username == "admin"`, returns the flag on success.
3. `GET /masks` – reveals the bit masks used during verification.

Passwords are reduced to integers via `x = bytes_to_long(password) % (p-1)`. The server stores two artefacts per user:
- `b = a^x mod p` with generator `a = 3` and a hidden 1536-bit prime `p`.
- SHA256 digests of `x & mask_i` for 103 published masks (each mask selects 80 bits from a ~200-bit window).

During authentication the service recomputes both values and compares them against the stored ones. A correct password must satisfy the discrete-log equality and every mask hash simultaneously.

## Step 1 – Reconstructing the Prime Modulus
`p` is not hard-coded but it can be recovered using the registration oracle:
1. Create a throwaway user with a short password (`"AA"`, `"AB"`, ...).
2. Trigger `/prove-id` with a wrong password to receive the error string which includes `b = 3^x mod p`.
3. Since `x` for our chosen password is known, compute `3^x - b`. The result is a multiple of `p`.
4. Repeat the process for a few passwords and take the GCD of all differences. The GCD yields the exact server modulus:

```
p = 1550794967883058437017735180318061520939800123551216575627895952591166840697406898606981811869589578681760370480836515879243585535110514128484499979778751236790371142977935209186374973188956272517830252443878693189026659469055916540395912490285451450287063108784681706041502544673128445155805186597876167620078628052447692279198427269250575400810903782227719825990919266422605430469972454854603958577919624434122366573120253588943917457640823265162291142268551169
```

## Step 2 – Extracting Low-Order Bits via Pohlig–Hellman
`p-1` factors as `2^150 * q` with a large odd `q`. Since the generator is 3, the discrete logarithm modulo `2^150` can be recovered efficiently:

1. Compute `g0 = 3^q mod p` and `h0 = b^q mod p` for the admin tuple obtained from the error string.
2. Use the standard binary lifting approach (Pohlig–Hellman for powers of two) to solve for the least-significant 150 bits of `x`.
3. Convert the result back to bytes: the final 19 characters of the admin password are revealed as `JAENuWluXA8TLxqcrZj`.

These bytes served as the seed for reconstructing the entire password.

## Step 3 – Digest Constraints from Masks
Each mask selects ~80 scattered bits across a 190-byte password window. The `/masks` endpoint provides all mask definitions. The error response when probing `admin` also lists SHA256 values for every masked subselection.

To recover the remaining bits:
1. Represent each mask as a list of absolute bit positions.
2. Seed a bit-map with the known suffix bits from Step 2.
3. For each mask, compute the known contribution `k = x & mask` using filled bits, and list the remaining unknown bit positions.
4. Perform a Gray-code enumeration over the unknown bits, progressively updating `k` and checking the SHA256 digest. Gray-code traversal ensures each iteration flips only one bit, turning an otherwise exponential search into a manageable loop. We begin with the mask that has the fewest unknown bits; solved masks inject new bits, reducing the search space for the remaining masks.

Repeating this procedure across all 103 masks eventually determines 186 of the 190 bytes. The unresolved bytes correspond to the first four characters but their bit patterns leave at most two alphabetic possibilities each.

Resulting partial password (first and last sections):
```
?t???8BGZ5UcIuJN43RFlxgxGWk...JAENuWluXA8TLxqcrZj
```

## Step 4 – Final Brute within the Character Set
The challenge specifies passwords consist of alphanumerics (`[A-Za-z0-9]`). Applying that constraint to the remaining two-bit gaps yields the following candidates:
- Byte 0: `G` or `O`
- Byte 2: forced to `E`
- Byte 3: `Q` or `U`
- Byte 4: forced to `5`

Testing the four combinations against both validation layers (discrete log and mask digests) reveals a single consistent password:
```
OtEU58BGZ5UcIuJN43RFlxgxGWklHDtw2kgwroJ2faif5aV1BxJJqNBm06sYFU2anJuLNzaqw2OUf846sSiZohASMkv0X1FRxIbMJnyiLu9u36n5l7KcHl42amAVcx5r2BKl8Y1wAJZa2KqzkK8WlsmBxhLOmxC99wfGBphLhC3JAENuWluXA8TLxqcrZj
```

Submitting this password to `/prove-id` authenticates successfully and returns the flag.

## Flag
```
EPFL{s0me_b1ts_ar3_really_ez_i_t0ld_ya}
```

## Takeaways
- Masked hash checks with no salt leak full information if an oracle returns all digest comparisons. Revealing the masks amplified the leakage.
- Most work came from eliminating the discrete-log search space; knowing the 2-adic component transforms the full 1535-bit exponent problem into a manageable bit-recovery puzzle.
- Gray-code enumeration is ideal for traversing mask assignments because each step updates a single bit and allows reuse of the running masked value.
