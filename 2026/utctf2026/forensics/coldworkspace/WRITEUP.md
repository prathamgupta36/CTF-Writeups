# Cold Workspace Writeup

## Challenge Info

- Name: `Cold Workspace`
- ID: `4`
- Category: `Forensics`
- Points: `837`
- Provided file: `cold-workspace.dmp`

## Summary

The dump looks like a Windows memory image, but the fast path is not full memory forensics tooling. The key artifact is a PowerShell process environment block that still contains all three values needed to reconstruct the deleted desktop file:

- `ENCD`: Base64 ciphertext
- `ENCK`: Base64 AES key
- `ENCV`: Base64 IV

Decrypting `ENCD` with AES-CBC using `ENCK` and `ENCV` recovers a small JPEG stub that embeds the flag text directly.

## Key Evidence

Searching the dump for the missing desktop artifact and PowerShell activity shows:

```text
cmdline(4608): powershell.exe -ExecutionPolicy Bypass -File C:\Users\analyst\Desktop\encrypt_flag.ps1
```

The same process keeps an environment block with:

```text
ENCD=...
ENCK=Ddf4BCsshqFHJxXPr5X6MLPOGtITAmXK3drAqeZoFBU=
ENCV=xXpGwuoqihg/QHFTM2yMxA==
```

That is enough to decrypt the missing desktop image without needing volatility symbol support.

## Recovery

The ciphertext is 144 bytes long, the key is 32 bytes, and the IV is 16 bytes, which fits AES-256-CBC.

After Base64-decoding all three fields and decrypting:

1. The plaintext begins with a JPEG header: `FF D8 FF E0`.
2. The payload contains embedded ASCII text.
3. The embedded text includes the flag.

## Solver

The automated extraction is in [solve.py](./solve.py).

Run:

```bash
python3 solve.py
```

## Flag

```text
utflag{m3m0ry_r3t41ns_wh4t_d1sk_l053s}
```
