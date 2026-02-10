# flag-finder (rev)

## Summary
The web page is a 1919‑checkbox grid. The JavaScript validates the grid against a massive regex; if the regex matches, it prints "Flag found". That regex encodes a nonogram: each column and row has run‑length constraints for `#` blocks. Solve the nonogram and read the rendered text to recover the flag.

## Steps

### 1) Fetch the regex
The page serves `script.js` which builds a 1919‑char string of `.` and `#` (one per checkbox) and tests it against `theFlag`.

```
const len = 1919;
const theFlag = /^(?=...)(?=^.{1919}$)...$/;
```

### 2) Parse constraints
The regex is a pile of lookaheads. Two parts matter:

- **Column constraints**: there are 101 lookaheads of the form `(?=(?:.{c}\..{100-c}){19}...)` which force a fixed `.`/`#` run pattern down each column (19 rows).
- **Row constraints**: later, it uses blocks like `(?<=.{101})(?<!.{102})(...)`, `(?<=.{202})(?<!.{203})(...)`, etc. Each block constrains the 101‑char row to a sequence of `#` runs separated by dots.

This clearly defines a **19 x 101 nonogram**.

### 3) Solve the nonogram
Model each cell `grid[r][c]` as a boolean in an SMT solver. For every row and column, constrain the positions of `#` runs to match the parsed run lengths.

Once solved, the grid is unique.

### 4) Read the text
Rendering the grid shows three lines of 3x5 glyphs (with one blank row between lines and one blank column between characters). Decode the custom font (lowercase + leetspeak digits). The message is:

```
Wh47 d0 y0u 637 wh3n y0u cr055 4 r363x 4nd 4 n0n06r4m? 4 r363x06r4m!
```

So the flag is:

```
lactf{Wh47_d0_y0u_637_wh3n_y0u_cr055_4_r363x_4nd_4_n0n06r4m?_4_r363x06r4m!}
```

## Notes
- There are two distinct glyphs for `W` vs `w`; the opening word is capitalized.
- The message is a pun: regex + nonogram = regexogram.
