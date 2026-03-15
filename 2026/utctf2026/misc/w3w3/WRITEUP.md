# W3W3 Writeup

## Challenge Info

- Name: `W3W3`
- Category: `Misc`
- Description: `The three words I would use to describe this location are...`
- Flag format: `utflag{word1.word2.word3}`
- Final flag: `utflag{inflate.deduces.cliff}`

## Overview

This challenge uses a reflection shot instead of a direct landmark photo. The visible clue is a large civic sign reflected in water, so the solve is:

1. Notice that the text is only visible through the reflection.
2. Read the reflected place name.
3. Resolve the accepted what3words square for that location.

## Key Observations

From [`W3W3.jpg`](./W3W3.jpg):

- Large white block letters are reflected in a pool.
- Red letter accents are also visible in the reflection.
- The text is cut off in the direct view at the top of the frame, so the reflection carries most of the readable information.

Flipping the image mentally points to the place name:

- `Aguas de Lindoia`

That corresponds to:

- `Águas de Lindóia`
- `São Paulo, Brazil`

## Accepted Square

Resolving the accepted three-word address gives:

- what3words: `inflate.deduces.cliff`
- coordinates: `-22.471230, -46.629479`
- nearest place: `Águas de Lindóia, São Paulo`

That matches the reflected civic sign in the image.

## Solution

The correct what3words address is:

- `inflate.deduces.cliff`

So the flag is:

```text
utflag{inflate.deduces.cliff}
```

## Summary

1. Treat the reflection as the readable version of the sign.
2. Read the place as `Águas de Lindóia`.
3. Resolve the accepted square at `-22.471230, -46.629479`.
4. Submit `utflag{inflate.deduces.cliff}`.
