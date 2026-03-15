# Oblivious Error Writeup

## Challenge

Category: Crypto

Files provided:

- `DESCRIPTION.md`
- `my-code.txt`

Remote:

```text
nc challenge.utctf.live 8379
```

The challenge says an RSA-based 1-out-of-2 oblivious transfer implementation was partially replaced with:

```python
while True:
    try:
        print("Please pick a value k.")
        k = int(input())
        break
    except ValueError:
        print("Invalid value. Please pick an integer.")
        print("Please pick a value k.")
        k = int(input())

v = (x0 + (int(k) ^ e)) % N
```

One of the messages becomes "undecodable", and the goal is to recover the lost message.

## Observations

The server prints:

- RSA modulus `N`
- public exponent `e`
- two random values `x0`, `x1`

Then it asks for `k` and returns two integer messages.

The important broken line is:

```python
v = (x0 + (int(k) ^ e)) % N
```

This is clearly suspicious for two reasons:

1. It always uses `x0`, so the normal OT structure is already broken.
2. It uses bitwise XOR with `e` instead of an RSA operation such as modular exponentiation.

Because XOR with a constant is reversible, we can choose `k` so that `v` becomes any value of the form `x0 + t (mod N)`.

In particular, we can force:

```text
v = x1
```

by choosing:

```text
k ^ e = (x1 - x0) mod N
```

so:

```text
k = ((x1 - x0) mod N) ^ e
```

## Why this leaks the message

In standard RSA 1-out-of-2 OT, the sender computes two masks from values derived from `v - x0` and `v - x1`.

If we force `v = x1`, then one of those differences becomes `0`. That means one sender-side mask is also `0`, so one returned ciphertext is actually just the plaintext integer itself.

When converted from a big integer to bytes, that plaintext reveals the flag directly.

The other message is a decoy:

```text
utflag{Congrats! You caught a red herring!}
```

## Exploit

The exploit script in [`solve.py`](/home/al/Downloads/CTF/utctf2026/crypto/obliviouserror/solve.py) does exactly that:

1. Connect to the remote service.
2. Parse `N`, `e`, `x0`, and `x1`.
3. Compute `k = ((x1 - x0) % N) ^ e`.
4. Send `k`.
5. Parse both returned integers.
6. Convert each integer to bytes and select the one containing `utflag{`.

## Solver

```python
k = ((x1 - x0) % n) ^ e
sock.sendall(f"{k}\n".encode())
```

## Result

Running:

```bash
python3 solve.py
```

prints:

```text
utflag{my_obl1v10u5_fr13nd_ru1n3d_my_c0de}
```

## Flag

```text
utflag{my_obl1v10u5_fr13nd_ru1n3d_my_c0de}
```
