# Faulty AES Writeup

## Challenge summary

The server splits `sha256(flag)` into:

- `key = sha256(flag)[:16]`
- `msg = sha256(flag)[16:]`

Then it asks us for a bit position, flips exactly that bit inside the source code of `aes.py`, executes the modified module, and returns one ciphertext:

```python
flag = os.environ.get("FLAG", "tkbctf{dummy}")
hash_val = hashlib.sha256(flag.encode()).digest()
key, msg = hash_val[:16], hash_val[16:]

pos = int(input("pos: "))
source = bytearray(inspect.getsource(aes), "utf-8")
source[pos // 8] ^= 1 << (pos % 8)
exec(bytes(source), aes.__dict__)

print("ct:", aes.AES(key).encrypt_block(msg).hex())
if bytes.fromhex(input("hash: ")) == hash_val:
    print(flag)
```

Source: [faulty-aes/server.py](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/crypto/faulty-aes/faulty-aes/server.py#L8)

So each connection gives us:

1. One chosen single-bit source mutation in `aes.py`
2. One AES encryption of a secret plaintext under a secret key
3. One chance to submit the full 32-byte `sha256(flag)`

The obvious problem is that both the key and plaintext are unknown. The useful part is that we control a bit flip in the implementation.

## The useful mutation

The last line of `encrypt_block` is:

```python
add_round_key(plain_state, self._key_matrices[-1])
```

Source: [faulty-aes/aes.py](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/crypto/faulty-aes/faulty-aes/aes.py#L208)

For AES-128, `self._key_matrices` has 11 round keys:

- `self._key_matrices[0] = K0`
- ...
- `self._key_matrices[10] = K10`

The character `'1'` in `[-1]` is ASCII `0x31`. Flipping bit `1` changes it to `0x33`, which is `'3'`. That turns:

- `self._key_matrices[-1]` into `self._key_matrices[-3]`

Since the list has length 11, index `-3` is round key `K8`.

So with that single bit flip, the final AES step changes from:

- normal: `ciphertext = T xor K10`

to:

- faulty: `ciphertext' = T xor K8`

where `T` is the state after the final `SubBytes` and `ShiftRows`, just before the last `AddRoundKey`.

This is exactly the kind of fault we want, because for the same secret key and plaintext:

```text
ciphertext xor ciphertext' = K10 xor K8
```

That removes the unknown state `T` completely.

## Getting a normal ciphertext

We also need one unmodified encryption result. The service always flips a bit, so we choose a harmless bit inside a docstring.

In the final solver I used the first bit of the string:

```text
"Encrypts a single block of 16 byte long plaintext."
```

This flips the leading `E` to `D`, which does not affect execution. That gives a normal AES ciphertext while still satisfying the server's “flip one bit” rule.

In the local file this neutral position is:

- `69120`

The useful `[-1] -> [-3]` position is:

- `73417`

The solver derives both positions from the local source instead of hardcoding them.

Source: [solve.py](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/crypto/faulty-aes/solve.py#L18)

## Why `K10 xor K8` is enough

Write the AES-128 expanded key as 4-byte words:

- `K8  = (w32, w33, w34, w35)`
- `K9  = (w36, w37, w38, w39)`
- `K10 = (w40, w41, w42, w43)`

Let:

```text
Delta = K10 xor K8 = (d0, d1, d2, d3)
```

where each `di` is one 4-byte word.

Using the AES-128 key schedule:

```text
w36 = w32 xor g(w35, 9)
w37 = w33 xor w36
w38 = w34 xor w37
w39 = w35 xor w38

w40 = w36 xor g(w39, 10)
w41 = w37 xor w40
w42 = w38 xor w41
w43 = w39 xor w42
```

Now simplify the words of `Delta`:

```text
d2 = w42 xor w34 = w40
d3 = w43 xor w35 = w41
d1 = w41 xor w33 = g(w39, 10)
d0 xor d1 = g(w35, 9)
```

So from `Delta` alone we get:

```text
w40 = d2
w41 = d3
w39 = g^-1(d1, 10) = w43 xor w42
w35 = g^-1(d0 xor d1, 9) = w43 xor w41
```

Then:

```text
w43 = (w43 xor w41) xor w41
w42 = w43 xor (w43 xor w42)
```

and we have the entire last round key:

```text
K10 = (w40, w41, w42, w43)
```

That is what `recover_last_round_key()` implements.

Source: [solve.py](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/crypto/faulty-aes/solve.py#L67)

## Recovering the master key and message

Once `K10` is known, we can invert the AES-128 key schedule backwards and recover `K0`, which is the original AES master key.

That is implemented in `invert_key_schedule()`.

Source: [solve.py](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/crypto/faulty-aes/solve.py#L80)

Now take the normal ciphertext `C` from the harmless-bit query and decrypt it with the recovered key:

```text
msg = AES(key).decrypt_block(C)
```

This yields the second half of `sha256(flag)`. Since:

```text
hash_val = key || msg
```

we recover the full 32-byte hash expected by the service.

## Full exploit flow

1. Connect once with a harmless docstring bit flip and record the normal ciphertext `C`.
2. Connect again with the bit flip that changes `self._key_matrices[-1]` to `self._key_matrices[-3]`, and record `C8`.
3. Compute `Delta = C xor C8 = K10 xor K8`.
4. Recover `K10` from `Delta`.
5. Invert the AES-128 key schedule to get the master key `K0`.
6. Decrypt `C` to recover `msg`.
7. Concatenate `K0 || msg` to get `sha256(flag)`.
8. Connect one more time and submit that hash.

This only needs three total connections to the remote service.

## Solver

The final solver is in:

- [solve.py](https://github.com/prathamgupta36/CTF-Writeups/blob/main/2026/tkbctf5_2026/crypto/faulty-aes/solve.py)

Key pieces:

- `get_bit_positions()` finds the neutral and useful bit flips from the local source.
- `query()` talks to the service.
- `recover_last_round_key()` reconstructs `K10` from `K10 xor K8`.
- `invert_key_schedule()` recovers the AES master key.

Running it:

```bash
python solve.py
```

Output:

```text
neutral_bit=69120
k8_bit=73417
sha256(flag)=1609ddfe35c023ca70eb1cd7d22718ae73947777ba14d88bfe3a3225d0c2f4c2
tkbctf{AES_is_n0t_s3cur3_ag4inst_ch0s3n_bit_f1ip_4ttacks!}
```

## Flag

```text
tkbctf{AES_is_n0t_s3cur3_ag4inst_ch0s3n_bit_f1ip_4ttacks!}
```
