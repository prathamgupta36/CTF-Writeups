# W3W2 Writeup

## Challenge Info

- Name: `W3W2`
- Category: `Misc`
- Description: `The three words I would use to describe this location are...`
- Flag format: `utflag{word1.word2.word3}`
- Final flag: `utflag{pilots.smokes.dinosaur}`

## Overview

This challenge is another image-to-what3words geolocation problem. The photo shows a small tropical storefront under a rainbow, so the solve reduces to:

1. Read the storefront sign.
2. Find the matching business.
3. Confirm the exact map point that the challenge accepts.

## Key Observations

From [`W3W2.jpg`](/home/al/Downloads/CTF/utctf2026/misc/w3w2/W3W2.jpg) and its local crops:

- [`store_crop.png`](/home/al/Downloads/CTF/utctf2026/misc/w3w2/store_crop.png)
- [`sign_crop.png`](/home/al/Downloads/CTF/utctf2026/misc/w3w2/sign_crop.png)
- [`sign_zoom.png`](/home/al/Downloads/CTF/utctf2026/misc/w3w2/sign_zoom.png)

The readable sign text is:

- `Merchandise & Gift Shop`
- smaller text consistent with `MAUI GIFTS`, `LOGO ITEMS`, and `TO GO SNACKS`

That immediately places the challenge on `Maui`.

## Identification

Searching the sign text leads to the business:

- `Merchandise & Gift shop`
- `61 S Kihei Rd`
- `Kihei, Hawaii`

This matches the storefront in the challenge image and the surrounding coastal/tropical environment.

The accepted square resolves to:

- what3words: `pilots.smokes.dinosaur`
- coordinates: `20.781681, -156.462385`
- nearest place: `Kihei, Hawaii`

That point is the business location itself.

## Solution

The correct what3words address is:

- `pilots.smokes.dinosaur`

So the flag is:

```text
utflag{pilots.smokes.dinosaur}
```

## Summary

1. Zoom the storefront sign until `Merchandise & Gift Shop` is readable.
2. Search the business name and match it to `61 S Kihei Rd, Kihei, Hawaii`.
3. Resolve that accepted point to `pilots.smokes.dinosaur`.
4. Submit `utflag{pilots.smokes.dinosaur}`.
