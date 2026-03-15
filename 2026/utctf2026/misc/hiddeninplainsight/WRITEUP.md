# Hidden in Plain Sight

## Summary

The challenge hides the flag in the challenge title itself using Unicode tag characters.

## Solution

The API returns the title as:

`Hidden \udb40\udc75\udb40\udc74\udb40\udc66\udb40\udc6c\udb40\udc61\udb40\udc67\udb40\udc7b\udb40\udc31\udb40\udc6e\udb40\udc76\udb40\udc31\udb40\udc73\udb40\udc31\udb40\udc62\udb40\udc6c\udb40\udc33\udb40\udc5f\udb40\udc75\udb40\udc6e\udb40\udc31\udb40\udc63\udb40\udc30\udb40\udc64\udb40\udc33\udb40\udc7d in Plain Sight`

Those surrogate pairs are Unicode tag characters in the `U+E0000` block. Subtracting `0xE0000` from each tag code point reveals ASCII characters, which decode directly to:

`utflag{1nv1s1bl3_un1c0d3}`

## Flag

`utflag{1nv1s1bl3_un1c0d3}`
