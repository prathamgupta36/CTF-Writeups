web/single-trust
r2uwu2
6 solves / 408 points
I was researching zero trust proofs in cryptography and now I have zero trust in JWT libraries so might roll my own.

Turns out, Aplet123 was researching zero trust proofs (web/zero-trust) a few years ago in LA CTF 2023.

I trust aplet so I'll just use his library (with his backdoor patched out).

$: diff single-trust/index.js zero-trust/index.js
47c47
<         res.locals.user = JSON.parse(Buffer.concat([cipher.update(ct), cipher.final()]).toString("utf8"));
---
>         res.locals.user = JSON.parse(cipher.update(ct).toString("utf8"));
single-trust.chall.lac.tf

Note: the flag is in /flag.txt
