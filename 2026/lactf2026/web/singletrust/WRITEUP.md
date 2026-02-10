# single-trust (LA CTF 2026) - Writeup

## Summary
The app stores an `auth` cookie containing AES-256-GCM encrypted JSON:

```
{"tmpfile":"/tmp/pastestore/<random>"}
```

The server decrypts this cookie on every request. The only "patch" from the
original Zero Trust challenge is calling `cipher.final()` during decryption,
which does *not* fix the core issue: the server accepts **truncated GCM auth
tags** because it never pins `authTagLength`. Node.js allows small tags (as low
as 1 byte on some versions), making brute-force feasible.

We can also exploit AES-CTR malleability to rewrite the JSON to point at
`/flag.txt` without knowing the random suffix length.

## Vulnerabilities
1. **Malleable AES-GCM ciphertext (CTR mode)**  
   In GCM, ciphertext = plaintext XOR keystream. Flipping ciphertext bytes
   flips the decrypted plaintext at the same positions.

2. **Truncated tag acceptance**  
   The server calls `decipher.setAuthTag(authTag)` without constraining tag
   length. If the client supplies a 1-byte tag, the server will accept it and
   authenticate only 8 bits. That means a successful forgery in ~256 tries on
   average.

## Attack Strategy
We transform the decrypted JSON so that the path becomes `/flag.txt` while
keeping the overall length identical:

```
Original: {"tmpfile":"/tmp/pastestore/<RAND>"}      (len L)
Target:   {"tmpfile":"/flag.txt","a":"<RAND>"}      (len L)
```

The unknown random suffix stays in place. Only known prefix bytes change.
We compute `ct' = ct XOR orig XOR target` for those bytes.

Then we brute-force a **1-byte auth tag**. If the tag is accepted, the server
decrypts the modified cookie and serves `/flag.txt` in the HTML.

## Steps
1. GET `/` to receive a fresh `auth` cookie.
2. Decode `iv`, `authTag`, and `ct` from the cookie.
3. Flip ciphertext bytes to rewrite the JSON to the target form.
4. Try auth tags of length 1; for each tag value 0..255:
   - Send `auth = iv . tag . ct'`
   - If valid, the response shows the flag.

## Result
Flag:

```
lactf{4pl3tc4tion_s3curi7y}
```

## Notes
The "patch" (adding `cipher.final()` during decryption) only enforces tag
verification *for the provided tag length*. The real fix is to set
`authTagLength` explicitly (e.g., 16 bytes) when creating and verifying the
GCM cipher.
