# Time to Pretend Writeup

## Challenge Info

- Name: `Time to Pretend`
- Category: `Web`
- Points: `947`
- Connection: `http://challenge.utctf.live:9382`
- Provided file: `aftechLEAK.pcap`

Challenge description:

> Did you hear about the big AffiniTech outage earlier this week? Earlier today, someone leaked some internal traffic of theirs on the darkweb as proof that they pwned the service. But I think there's more here than just logs; maybe you can break in too?

## Goal

Recover enough information from the leaked traffic to authenticate to the live service and retrieve the flag.

## Files in the Challenge Directory

- `DESCRIPTION.md`: local challenge metadata
- `aftechLEAK.pcap`: leaked internal traffic
- `solve.py`: automated solver written during the solve

## High-Level Plan

1. Inspect the PCAP to determine what internal endpoint was leaked.
2. Recover the OTP generation logic from the captured request/response pairs.
3. Enumerate the live web app for hidden hints about which account is still usable.
4. Generate the current OTP for the correct account.
5. Log in, fetch `/portal`, and extract the flag.

## Step 1: Inspecting the PCAP

The capture is small and contains only HTTP traffic. A quick `tshark` pass shows all of the interesting application traffic is going to a single endpoint:

```bash
tshark -r aftechLEAK.pcap -Y http -T fields \
  -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri
```

Every request is:

```text
POST /debug/getOTP
```

The request bodies contain JSON with:

- `username`
- `epoch`

The responses contain JSON with:

- `add`
- `mult`
- `otp`

Decoded examples from the capture:

```text
1: {'username': 'carrasco', 'epoch': 1773290571} -> {'add': 13, 'mult': 7, 'otp': 'bnccnjbh'}
2: {'username': 'mix', 'epoch': 1773290574} -> {'add': 16, 'mult': 15, 'otp': 'ogx'}
3: {'username': 'hebert', 'epoch': 1773290575} -> {'add': 17, 'mult': 17, 'otp': 'ghihuc'}
4: {'username': 'monks', 'epoch': 1773290576} -> {'add': 18, 'mult': 19, 'otp': 'myfaw'}
5: {'username': 'eyre', 'epoch': 1773290577} -> {'add': 19, 'mult': 21, 'otp': 'zdmz'}
6: {'username': 'jurado', 'epoch': 1773290579} -> {'add': 21, 'mult': 25, 'otp': 'mbevsh'}
```

This is already a major leak: the debug endpoint exposes not just the OTP output, but also the exact parameters used to build it.

## Step 2: Reversing the OTP Algorithm

The responses strongly suggest an affine transform over lowercase letters:

```text
cipher_char = (mult * plain_char + add) mod 26
```

Where letters are mapped as:

```text
a = 0
b = 1
...
z = 25
```

### Recovering `add`

From the capture:

```text
epoch = 1773290571, add = 13
epoch = 1773290574, add = 16
epoch = 1773290575, add = 17
```

Checking modulo 26:

```text
1773290571 % 26 = 13
1773290574 % 26 = 16
1773290575 % 26 = 17
```

So:

```text
add = epoch % 26
```

### Recovering `mult`

The `mult` values observed in the capture are:

```text
1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25
```

Those are exactly the invertible elements modulo 26. That is what you would use for an affine cipher if you wanted the transform to stay reversible.

The value changes predictably with the epoch. The pattern is:

```python
VALID_MULTS = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
mult = VALID_MULTS[epoch % 12]
```

### Full OTP Function

For a lowercase username:

```python
VALID_MULTS = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

def generate_otp(username, epoch):
    add = epoch % 26
    mult = VALID_MULTS[epoch % 12]
    out = []
    for ch in username:
        p = ord(ch) - ord("a")
        c = (mult * p + add) % 26
        out.append(chr(c + ord("a")))
    return "".join(out)
```

### Sanity Check

Take the first leaked sample:

```text
username = carrasco
epoch    = 1773290571
add      = 13
mult     = 7
```

For the first character, `c = 2`:

```text
(7 * 2 + 13) % 26 = 27 % 26 = 1 = b
```

The produced OTP starts with `b`, which matches the capture:

```text
bnccnjbh
```

So the reconstruction is consistent with the leak.

## Step 3: Recon on the Live Service

Requesting `/` returns a flashy landing page with a login form that POSTs to `/auth` and redirects to `/portal` on success.

More importantly, the page source contains a developer comment:

```html
<!-- NOTICE to DEVS: login currently disabled, see /urgent.txt for info -->
```

It also explicitly references the old debug leak:

```html
// Request your AffinKey™ OTP via the debug endpoint
```

Fetching `/urgent.txt` gives the missing operational detail:

```text
i have locked every account in the system except mine while we figure this out.
...
my account stays active because i need access to keep monitoring the situation.
...
- timothy
```

This tells us:

- most leaked usernames from the PCAP are no longer useful
- the only account that should still authenticate is `timothy`

## Step 4: Exploitation Strategy

At this point the exploit is straightforward:

1. Set the username to `timothy`.
2. Generate the OTP using the current epoch.
3. Try a small time window around the local clock in case of small skew between client and server.
4. Submit the correct pair to `/auth`.
5. Reuse the returned session cookie to request `/portal`.
6. Extract the flag from the portal HTML.

Because the OTP depends on the exact current second, trying a short range such as `now - 15` through `now + 15` is enough.

## Step 5: Automated Solver

The final solver is in `solve.py`.

It does three things:

1. Requests `/urgent.txt` and extracts the active username from the `FROM:` line.
2. Brute-forces a small epoch window around the current time while generating OTPs with the recovered affine function.
3. On successful login, requests `/portal` and regexes out the flag.

Core parts of the script:

```python
VALID_MULTS = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]

def generate_otp(username: str, epoch: int) -> str:
    add = epoch % 26
    mult = VALID_MULTS[epoch % 12]
    return "".join(
        chr((mult * (ord(ch) - ord("a")) + add) % 26 + ord("a"))
        for ch in username
    )
```

Run it with:

```bash
python solve.py
```

Example successful output:

```text
username: timothy
epoch: 1773375714
otp: fweifhc
flag: utflag{t1m3_1s_n0t_r3l1@bl3_n0w_1s_1t}
```

## Final Flag

```text
utflag{t1m3_1s_n0t_r3l1@bl3_n0w_1s_1t}
```

## Why the Challenge Works

The challenge combines three small weaknesses:

1. A debug endpoint leaked internal OTP generation data in plaintext.
2. The OTP system used a weak affine cipher keyed only by time, not a secret.
3. The live app exposed a hidden operational note that disclosed the only still-active user.

Individually, each issue is bad. Together, they fully compromise authentication.

## Takeaways

- Never expose debug endpoints containing secrets or internal derivation parameters.
- OTPs must be based on a secret, not only public data such as the current time.
- Homemade crypto is almost always a bad idea.
- Hidden paths in HTML comments are still public.
- Operational notes should never be deployed with the application.
