# Breadcrumbs

## Summary

Starting from the URL in `DESCRIPTION.md`, the challenge is a short OSINT-style breadcrumb trail across public GitHub gists.

## Solution

1. The first gist contained a Base64 string:

   `aHR0cHM6Ly9naXN0LmdpdGh1Yi5jb20vZ2FydmswNy9iYTQwNjQ2MGYyZTkzMmI1NDk2Y2EyNTk3N2JlMjViZQ==`

   Decoding it gives the next gist:

   `https://gist.github.com/garvk07/ba406460f2e932b5496ca25977be25be`

2. The second gist included a poem plus a `p.s.` link to another gist:

   `https://gist.github.com/garvk07/963e70be662ea81e96e4e63553038d1a`

3. The third gist hid a hex string inside a Python comment:

   `68747470733a2f2f676973742e6769746875622e636f6d2f676172766b30372f3564356566383539663533306333643539336134613363373538306432663239`

   Hex-decoding it gives the final gist:

   `https://gist.github.com/garvk07/5d5ef859f530c3d593a4a3c7580d2f29`

4. The final gist contained:

   `hgsynt{s0yy0j1at_gu3_pe4jy_ge41y}`

   Applying ROT13 yields the flag.

## Flag

`utflag{f0ll0w1ng_th3_cr4wl_tr41l}`
