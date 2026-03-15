# Break the Bank Writeup

## Challenge Info

- Name: `Break the Bank`
- ID: `22`
- Category: `Web`
- Points: `938`
- Solves: `80`
- Target: `http://challenge.utctf.live:5926`

## Summary

This challenge is a broken authentication design hidden behind a retro banking UI.

The application uses a cookie named `fnsb_token` and stores a compact JWE in it. The critical mistake is that the server treats an encrypted token as if encryption alone proves authenticity. Because the site also exposes a directory listing under `/resources/`, it leaks the public key used for JWE encryption at `/resources/key.pem`.

That public key is enough to mint a brand new token with arbitrary claims. By forging a token whose decrypted JSON body is:

```json
{"sub":"admin"}
```

we can access `/admin` and read the flag.

## Final Flag

```text
utflag{s0m3_c00k1es_@re_t@st13r_th@n_0th3rs}
```

## Recon

The challenge directory only contained [DESCRIPTION.md](./DESCRIPTION.md), so the solve started from live interaction with the target.

### 1. Main page

Requesting `/` showed a static-looking bank homepage with one real link:

```text
/login.html
```

### 2. Login page behavior

The login page contains client-side JavaScript that sends credentials to:

```text
POST /login
Content-Type: application/json
```

On success it receives a JSON object with:

- `token`
- `redirect`

and the server also sets a `fnsb_token` cookie.

### 3. Demo credentials from the PDF

The homepage links to `/resources/FNSB_InternetBanking_Guide.pdf`. Extracting text from that PDF reveals demo credentials:

```text
Username: testuser
Password: testpass123
```

Logging in with those credentials returns a large token and redirects to `/profile`.

### 4. Privilege boundary

After authenticating as the demo user:

- `/profile` returns the account summary page
- `/admin` returns:

```json
{"error":"Forbidden: admin subject required"}
```

That error message is important. It shows authorization is based on a token claim named `sub`, and the admin console is likely gated only by `sub == "admin"`.

## The Real Break

While enumerating obvious content, `/resources/` turned out to be directory-indexed:

```text
/resources/
  memo.txt
  key.pem
  FNSB_InternetBanking_Guide.pdf
```

This is the core mistake.

### Why `key.pem` matters

`/resources/key.pem` contains:

```pem
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

At first glance, leaking only a public key may not look fatal. But for JWE, the public key is specifically what anyone uses to encrypt data for the holder of the private key.

That means:

1. Anyone can encrypt a payload using the public key.
2. The server can decrypt it with its private key.
3. If the server mistakes "successfully decrypted" for "trusted identity", the attacker fully controls the claims.

That is exactly what happens here.

## Exploit Strategy

The compact token format used by the app is:

```text
BASE64URL(protected_header).
BASE64URL(encrypted_key).
BASE64URL(iv).
BASE64URL(ciphertext).
BASE64URL(tag)
```

The protected header used by the legitimate application is:

```json
{"cty":"JWT","enc":"A256GCM","alg":"RSA-OAEP-256"}
```

To forge an admin token:

1. Download the leaked public key from `/resources/key.pem`.
2. Generate a random 256-bit content-encryption key.
3. Encrypt that CEK using RSA-OAEP-256 and the leaked public key.
4. Encrypt the JSON payload `{"sub":"admin"}` with AES-256-GCM.
5. Use the base64url-encoded protected header as the GCM AAD, as required by compact JWE.
6. Assemble the five-part compact JWE.
7. Send it as the `fnsb_token` cookie to `/admin`.

The server accepts the forged token and treats the decrypted JSON as authenticated claims.

## Reproduction

The repository now includes [solve.py](./solve.py), which performs the full attack.

Run:

```bash
python solve.py
```

Expected output:

```text
utflag{s0m3_c00k1es_@re_t@st13r_th@n_0th3rs}
```

## Solver Walkthrough

`solve.py` does the following:

### 1. Fetch the exposed public key

```python
pub_pem = requests.get(f"{base_url}/resources/key.pem", timeout=10).text.encode()
pubkey = serialization.load_pem_public_key(pub_pem)
```

### 2. Create the JWE protected header

```python
PROTECTED_HEADER = b'{"cty":"JWT","enc":"A256GCM","alg":"RSA-OAEP-256"}'
```

### 3. Encrypt a chosen plaintext payload

The chosen plaintext is:

```json
{"sub":"admin"}
```

That payload is encrypted under a random AES key, and the AES key is encrypted with the leaked RSA public key.

### 4. Send the forged token as the session cookie

```python
requests.get(
    f"{base_url}/admin",
    headers={"Cookie": f"fnsb_token={token}"},
    timeout=10,
)
```

### 5. Extract the flag from the admin page

The script searches the HTML for:

```python
utflag\{[^}]+\}
```

## Why the Attack Works

The vulnerability is not "JWE is broken". The vulnerability is misuse of JWE.

JWE provides confidentiality. It does not provide trust by itself.

If a server wants to trust claims, it must verify authenticity, for example by:

- using a signed JWS and verifying the signature
- using a nested signed-then-encrypted token
- maintaining server-side session state instead of trusting client-supplied claims

This challenge instead accepts any token that:

1. decrypts correctly with the private key
2. contains the right claim values

Because the public key was exposed, the attacker can produce a perfectly decryptable token with any subject they want.

## Additional Notes

Two other findings helped confirm the path:

- The PDF in `/resources/FNSB_InternetBanking_Guide.pdf` exposed `testuser:testpass123`, which provided a baseline valid session.
- The error from `/admin` for that user explicitly said `admin subject required`, which strongly suggested the target claim to forge.

Neither of those alone was enough to solve the challenge, but together they narrowed the attack quickly.

## Root Cause

This is really a combination of two issues:

1. Sensitive file exposure via directory listing under `/resources/`
2. Treating encrypted client-side claims as authenticated identity

Either issue is bad. Together they completely break access control.

## Remediation

If this were a real application, the fixes would be straightforward:

- Disable directory indexing for static resources.
- Never expose key material in a public static directory.
- Do not treat JWE confidentiality as proof of authenticity.
- Sign tokens and verify signatures before trusting claims.
- Prefer opaque server-side session identifiers for authentication.
- Avoid authorization decisions based only on untrusted client-managed claims.

## Short Version

The bank leaked its JWE public key in a browsable static directory. The server then accepted any decryptable JWE as a valid authenticated token. Encrypting `{"sub":"admin"}` with the leaked public key yielded an admin session and the flag.
