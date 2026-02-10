# Misdirection (crypto) Writeup

## Challenge summary

The server implements a game where you must grow a snake to length 14 to claim
the flag. Each `/grow` request must include a valid NTRU signature over the
current count. The server intentionally slows down signature generation and
limits growth once the count reaches 4 unless the client can keep producing
valid signatures.

Key endpoints:

- `GET /zero-signature` returns the signature for count 0.
- `POST /grow` verifies a signature over the supplied count and increments
  `current_count` by 1 if valid.
- `POST /flag` returns the flag if `current_count >= 14`.

## Intended break

The verification function in `NTRUSign/NTRU.py` checks:

```
b = NTRUNorm(s, s.star_multiply(k.pub) - m, (0, k.q))
return b < N_bound
```

The hash polynomial `m = H(D || r)` is relatively small. For this parameter
set, its centered Euclidean norm is always below `N_BOUND = 545`.
That means the *all-zero signature* (`s = 0`) will always verify, regardless
of the public key or message, as long as the `r` value can be parsed.

So we can forge a valid signature for any count by submitting:

- all coefficients of `s` equal to 0 (length 251)
- any integer `r` (use 0)

The server accepts any `sig` string matching the parser format, and does not
enforce the expected coefficient length or restrict `r`.

## Second bug: race in `/grow`

The `/grow` handler checks:

```
if current_count < 4 and client_count == current_count:
    verify signature
    current_count += 1
```

There is no lock around `current_count`. If we send many concurrent requests
with the *same* `client_count`, all of them pass the `current_count < 4`
check before any increments happen, then each request increments the counter.

This lets us jump from 0 to 14+ in a single burst.

## Exploit strategy

1. Wait for `/status` to become ready.
2. Build a forged signature with all-zero coefficients and `r = 0`.
3. Read `/current-count` (normally 0 after reset).
4. Fire a large concurrent burst of `POST /grow` requests with the same count
   and the forged signature.
5. After the burst, check `/current-count`. If it is at least 14, call `/flag`.

This is a race and depends on server timing. If it fails:

- call `/regenerate-keys`
- wait for `/status`
- retry with a larger burst

## Proof of forge (local reasoning)

For `s = 0`:

```
b = NTRUNorm(0, -m, (0, 128)) = ||m||_centered
```

Empirically (and consistent with the hash construction), `||m||_centered` is
around 400, always below 545, so verification always returns true.

## Example exploit script

```python
import asyncio, ssl, json, time
import requests

HOST = "misdirection-qo2mq.instancer.lac.tf"
BASE = "https://misdirection-qo2mq.instancer.lac.tf"

# wait ready
while True:
    try:
        if requests.get(BASE + "/status", timeout=10).json().get("status"):
            break
    except Exception:
        pass
    time.sleep(1)

count = requests.get(BASE + "/current-count", timeout=10).json()["count"]
print("starting count", count)

N = 251
SIG = (
    "-----BEGIN NTRU SIGNATURE BLOCK-----\n"
    + "|".join(["0"] * N)
    + "\n==0\n"
    + "-----END NTRU SIGNATURE BLOCK-----\n"
)

body = json.dumps({"count": count, "sig": SIG}).encode("utf-8")
req = (
    f"POST /grow HTTP/1.1\r\n"
    f"Host: {HOST}\r\n"
    "Content-Type: application/json\r\n"
    f"Content-Length: {len(body)}\r\n"
    "Connection: close\r\n\r\n"
).encode("utf-8") + body

ssl_ctx = ssl.create_default_context()

async def send_one():
    try:
        reader, writer = await asyncio.open_connection(HOST, 443, ssl=ssl_ctx)
        writer.write(req)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

async def main(n):
    tasks = [asyncio.create_task(send_one()) for _ in range(n)]
    await asyncio.gather(*tasks)

# tune this depending on latency
asyncio.run(main(900))

while True:
    try:
        if requests.get(BASE + "/status", timeout=10).json().get("status"):
            break
    except Exception:
        pass
    time.sleep(1)

count = requests.get(BASE + "/current-count", timeout=10).json()["count"]
print("after blast count", count)

if count >= 14:
    print(requests.post(BASE + "/flag", json={}, timeout=10).json())
else:
    print("retry with more concurrency or regenerate keys")
```

## Flag

```
lactf{d0nt_b3_n0nc00p3r4t1v3_w1th_my_s3rv3r}
```
