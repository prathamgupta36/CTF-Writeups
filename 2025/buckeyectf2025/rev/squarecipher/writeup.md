# Buckeye CTF 2025 — rev/Square Cipher (449 pts)

This “cipher” is a one‑liner Python program that reads a hex number and checks bitwise constraints. The twist: each bit of certain masks selects an entire hex nibble (4 bits) of your input, so the puzzle becomes a 9×9 grid where each cell is a nibble with a popcount (0–4). The 27 constraints are the 9 rows, 9 columns, and 9 boxes of this grid, each summing to 15 — a Sudoku‑like sum puzzle with extra fixed bits.

## Files
- `description.md`: short challenge blurb + remote host/port
- `square_cipher.py`: the validating one‑liner

## Core Idea
The code translates each integer `y` in a fixed list to a nibble‑selector mask:
- `bin(y)` → e.g., `0b101…`
- `translate(str.maketrans('1b','fx'))` → replace `'b'` with `'x'` and every `'1'` bit with `'f'`
- `int(..., 0)` → interpret `0x...` as hex, so each `1` in `y` becomes a nibble mask `0xF` in the same position

For your input `x` (as a big hex integer):
- `(mask(y) & x).bit_count()` equals the sum of bitcounts of the 9 nibbles selected by nonzero bits in `y`
- The code checks this equals `15` for 27 different `y`s
- Those 27 `y`s are: 9 rows (consecutive nibble indices), 9 columns (stride 9), and 9 boxes (3×3 blocks) over 81 nibbles

There’s also a hard mask constraint on `x`:
- `x & A == B` where `A` and `B` are 320‑bit constants
- Bits where `A` has `1` are fixed: if `B` has `1` the corresponding bit in `x` must be `1`, otherwise it must be `0`
- This forces some nibble bits and thus partially fixes each cell’s popcount

## Solving Strategy
1. Interpret `x` as 81 nibbles (cells) → each cell’s popcount `w[i] ∈ {0,1,2,3,4}`.
2. From `x & A == B`, compute for each cell:
   - `forced_one[i]` = how many bits in its nibble are forced to 1 by `B`
   - `free_bits[i]` = how many bits in its nibble remain free (not set by `A`)
   - Domain: `w[i] ∈ [forced_one[i], forced_one[i] + free_bits[i]]`
3. Build the 27 groups (9 rows, 9 cols, 9 boxes) from the provided `y`s.
4. Solve the integer constraints: for every group, sum of its 9 `w[i]` equals 15.
   - Use DFS with MRV (smallest domain first) + forward‑checking on group lower/upper bounds.
5. Once `w` is found, construct a concrete `x` nibble‑by‑nibble:
   - Start with the forced 1/0 bits from `A,B`
   - For each nibble, turn on the lowest available free bits until its popcount equals `w[i]`
6. Validate all 27 `(mask(y) & x).bit_count() == 15` and `x & A == B` locally, then send the hex to remote.

## Result
- Working input (hex, no `0x`):
  - `7986770014039003ff5f033287073757003060f100f78001ff146534311f1078f9426f0013008f62f`
- Remote interaction:
  - `ncat --ssl square-cipher.challs.pwnoh.io 1337`
  - Paste the hex above
- Flag:
  - `bctf{5um_0f_f1r57_n_0dd_numb3r5_c1ph3r_025165aa}`

## Reference Solver (Python)
This is a cleaned version of the local solver that reconstructs the groups, solves for popcounts, builds a satisfying `x`, and prints the hex.

```python
A = 2135465562637171390290201561322170738230609084732268110734985633502584038857972308065155558608880
B = 1271371190459412480076309932821732439054921890752535035282222258816851982409101952239053178406432
ys = [
    511,261632,1838599,14708792,117670336,133955584,68585259008,35115652612096,
    246772580483072,1974180643864576,15793445150916608,17979214137393152,
    9205357638345293824,4713143110832790437888,4731607904558235517441,
    9463215809116471034882,18926431618232942069764,33121255085135066300416,
    37852863236465884139528,75705726472931768279056,151411452945863536558112,
    264970040681080530403328,302822905891727073116224,605645811783454146232448,
    1211291623566908292464896,2119760325448644243226624,2413129272746388704198656
]

# Build 9 rows, 9 cols, 9 boxes over 81 nibble indices
rows, cols, boxes = [None]*9, [None]*9, []
for y in ys:
    g = [i for i in range(y.bit_length()) if (y>>i)&1]
    if g == list(range(g[0], g[0]+9)):
        rows[g[0]//9] = g
    elif all((g[i+1]-g[i]==9) for i in range(8)):
        cols[g[0]%9] = g
    else:
        boxes.append(g)
all_groups = rows + cols + boxes

cells = 81
forced_one = [0]*cells
free_bits  = [4]*cells
forced_one_mask  = [0]*cells
forced_zero_mask = [0]*cells
for i in range(cells):
    for b in range(4):
        bitpos = 4*i + b
        if (A>>bitpos) & 1:
            free_bits[i] -= 1
            if (B>>bitpos) & 1:
                forced_one[i] += 1
                forced_one_mask[i] |= (1<<b)
            else:
                forced_zero_mask[i] |= (1<<b)

domain = [(forced_one[i], forced_one[i]+free_bits[i]) for i in range(cells)]
cell_groups = [[] for _ in range(cells)]
for gi, g in enumerate(all_groups):
    for i in g:
        cell_groups[i].append(gi)

# DFS with forward checking to assign popcounts w[i]
T = 15
w = [-1]*cells
order = sorted(range(cells), key=lambda i: (domain[i][1]-domain[i][0], i))
current_sum = [0]*len(all_groups)
current_min_remaining = [sum(domain[i][0] for i in g) for g in all_groups]
current_max_remaining = [sum(domain[i][1] for i in g) for g in all_groups]

def dfs(idx=0):
    if idx == len(order):
        return True
    i = order[idx]
    lo, hi = domain[i]
    for val in range(lo, hi+1):
        saved = []
        ok = True
        for gi in cell_groups[i]:
            saved.append((gi, current_sum[gi], current_min_remaining[gi], current_max_remaining[gi]))
            current_sum[gi] += val
            current_min_remaining[gi] -= domain[i][0]
            current_max_remaining[gi] -= domain[i][1]
            if current_sum[gi] + current_min_remaining[gi] > T or \
               current_sum[gi] + current_max_remaining[gi] < T:
                ok = False
                break
        if ok:
            w[i] = val
            if dfs(idx+1):
                return True
            w[i] = -1
        for gi, s, mn, mx in saved:
            current_sum[gi], current_min_remaining[gi], current_max_remaining[gi] = s, mn, mx
    return False

assert dfs()

# Build nibble values consistent with w and forced masks
nibbles = [0]*cells
for i in range(cells):
    need = w[i] - forced_one[i]
    val = forced_one_mask[i]
    for b in range(4):
        if need == 0:
            break
        bitpos = 4*i + b
        if ((A>>bitpos) & 1) == 0:  # free bit
            val |= (1<<b)
            need -= 1
    assert need == 0 and (val & forced_zero_mask[i]) == 0
    assert (val & 0xF).bit_count() == w[i]
    nibbles[i] = val & 0xF

x = 0
for i in range(cells):
    x |= (nibbles[i] << (4*i))

# Quick validation
trans = str.maketrans('1b','fx')
for y in ys:
    M = int(bin(y).translate(trans), 0)
    assert (M & x).bit_count() == 15
assert (x & A) == B

print(format(x, 'x'))
```

## Why “Square Cipher”?
- The 81 nibbles form a 9×9 square.
- Each of the 27 masks encodes a row, column, or 3×3 square — classic Sudoku structure — but the rule is a fixed sum (15), not distinct digits.

Happy reversing!
