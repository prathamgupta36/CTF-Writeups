# Crab Mentality Writeup

## Challenge Info

- Name: `Crab Mentality`
- ID: `23`
- Category: `Web`
- Points: `981`
- Connection: `http://challenge.utctf.live:5888`

## Summary

The application exposes a file-read endpoint:

```text
/getFlag?f=<path>
```

Even though the challenge text frames the solve as a "wait your turn" problem, the server trusts the `f` parameter and allows directory traversal. Reading a backup source file reveals the flag bytes directly.

## Exploit

Request:

```text
GET /getFlag?f=../main.py.bak
```

The returned backup source contains the flag encoded as a list of hex byte literals. Extracting those `0x..` values and converting them back to bytes yields the flag.

## Solver

The automated solver is in [solve.py](/home/al/Downloads/CTF/utctf2026/web/crabmentality/solve.py).

It:

1. Downloads `../main.py.bak` through the traversal bug.
2. Regex-extracts all `0x??` byte values.
3. Decodes them into ASCII.

Run:

```bash
python3 solve.py
```

## Flag

```text
utflag{y0u_e1th3r_w@1t_yr_turn_0r_cut_1n_l1ne}
```
