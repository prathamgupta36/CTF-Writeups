# Silent Archive Writeup

## Challenge Info

- Name: `Silent Archive`
- ID: `9`
- Category: `Forensics`
- Points: `877`
- Provided file: `freem4.zip`

## Summary

The challenge split into two independent clues:

1. `File2.tar` is a 1000-layer tar nesting that ends in an encrypted ZIP.
2. `File1.tar` contains two JPEGs that look identical, but each has appended telemetry text after the JPEG end marker.

The second image branch leaks the ZIP password. The encrypted text file inside the final ZIP then stores the flag as whitespace binary using spaces and tabs.

## Archive Branch

`freem4.zip` contains:

- `File1.tar`
- `File2.tar`
- `README.txt`

Listing `File2.tar` shows a countdown:

```text
999.tar -> 998.tar -> ... -> 0 ...
```

Walking that chain eventually lands on `Noo.txt`, which is not a text file at all but an encrypted ZIP archive containing:

- `NotaFlag.txt`
- `notes.md`

## Image Branch

`File1.tar` contains:

- `cam_300.jpg`
- `cam_301.jpg`

The rendered images are visually identical, so the useful difference is not in pixels. Looking at the tail of each JPEG reveals extra appended text:

```text
AUTH_FRAGMENT_B64:QWx3YXlzX2NoZWNrX2JvdGhfaW1hZ2Vz
AUTH_FRAGMENT_B64:MHI0bmczX0FyQ2gxdjNfVDRiU3A0Y2Uh
```

Decoding those Base64 fragments gives:

```text
Always_check_both_images
0r4ng3_ArCh1v3_T4bSp4ce!
```

The second fragment is the actual password for the encrypted ZIP.

## Recovering the Flag

Using password `0r4ng3_ArCh1v3_T4bSp4ce!` unlocks `NotaFlag.txt`. Its contents are only spaces, tabs, and newlines. Each line is 8 characters long, so treating:

- space = `0`
- tab = `1`

and decoding each line as one byte produces the flag.

## Solver

The automated extraction is in [solve.py](./solve.py).

Run:

```bash
python3 solve.py
```

## Flag

```text
utflag{d1ff_th3_tw1ns_unt4r_th3_st0rm_r34d_th3_wh1t3sp4c3}
```
