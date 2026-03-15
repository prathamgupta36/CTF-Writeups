# README.pdf

- Status: solved and submitted
- Flag: `tkbctf{J4v4Scr1pt_1n_PDF}`

## Method

The PDF is interactive and contains embedded JavaScript. Extracting the objects with `strings` shows:

```javascript
var expected = [46,49,56,57,46,60,33,16,110,44,110,9,57,40,107,42,46,5,107,52,5,10,30,28,39];
var k = 90;
```

The checker validates `input_buf.charCodeAt(i) ^ k === expected[i]`, so the flag is recovered by XORing each entry with `90`.

## Reproduction

```bash
python3 - <<'PY'
expected = [46,49,56,57,46,60,33,16,110,44,110,9,57,40,107,42,46,5,107,52,5,10,30,28,39]
print(''.join(chr(x ^ 90) for x in expected))
PY
```
