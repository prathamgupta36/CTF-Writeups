# rev/the-fish (pstorm)

## Challenge information
- Category: reverse engineering
- Name: rev/the-fish
- Author: pstorm
- Solves / Points: 23 solves / 311 points
- Prompt: "The fish asks you for the flag. Unfortunately, it can only describe it to you in its own words."
- Files: `fish.py`

## Summary
The program is a small interpreter for a custom esolang. The provided program (`fisherator`) takes the user input (flag string), transforms it into a large integer using base-256 accumulation, then repeatedly applies a Collatz-style update while encoding the parity bits into another integer. That encoded value is compared against a constant. Reversing the parity encoding reconstructs the original integer, which converts directly to the flag bytes.

## Solution walkthrough

### 1) Understand the interpreter
`fish.py` defines a 1D program (the `fisherator` string) executed by the `Interpreter` class. The main logic is:

- Read the user input: `flag = input(...)`
- Push each character as its ASCII code onto the stack.
- Run the `fisherator` program.
- The `n` instruction checks if a computed integer equals a fixed constant; if so, it prints success.

So the goal is to understand how `fisherator` maps the input string to that integer.

### 2) Observe the two phases
Running and tracing the program shows two distinct phases:

1) **Fold the flag bytes into a big integer `N`.**
   - The program iterates over the characters on the stack.
   - It constructs `N` as if the bytes are in big-endian order:
     ```
     N = 0
     for b in flag_bytes:
         N = N * 256 + b
     ```

2) **Encode Collatz parity into `acc`.**
   - It then runs a loop while `N != 1`:
     - Append the current parity bit to `acc` via `acc = acc * 2 + (N % 2)`.
     - Update `N` using a Collatz-like rule (odd step is combined):
       - If `N` is even: `N = N / 2`
       - If `N` is odd: `N = (3 * N + 1) / 2`

Finally, the program compares `acc` to a hardcoded constant. If they match, it prints the success message.

### 3) Reverse the parity encoding
The encoding is reversible because `acc` is built by left-shifting and adding the parity bit each step. In binary, `acc` looks like:

- `acc = 1` initially
- At each step: `acc = (acc << 1) | parity`

So the binary representation of `acc` is:

```
1 [parity bits in order]
```

To reverse it:

1) Extract `acc` from `fish.py` (the constant in the `n` instruction).
2) Convert to binary and drop the leading `1`.
3) Process the parity bits in **reverse** to recover `N`:
   - Start from `n = 1`.
   - For each bit `b` from last to first:
     - If `b == 0`, previous value was even: `n = n * 2`.
     - If `b == 1`, previous value was odd: `n = (2 * n - 1) / 3`.

This yields the original `N` used by the program.

### 4) Convert `N` back to bytes
Since `N` was built as base-256 big-endian, we convert it back into bytes and decode as ASCII. The resulting string is the flag.

## Solver script (reference)

```python
# Extracted constant from fish.py
ACC = 996566347683429688961961964301023586804079510954147876054559647395459973491017596401595804524870382825132807985366740968983080828765835881807124832265927076916036640789039576345929756821059163439816195513160010797349073195590419779437823883987351911858848638715543148499560927646402894094060736432364692585851367946688748713386570173685483800217158511326927462877856683551550570195482724733002494766595319158951960049962201021071499099433062723722295346927562274516673373002429521459396451578444698733546474629616763677756873373867426542764435331574187942918914671163374771769499428478956051633984434410838284545788689925768605629646947266017951214152725326967051673704710610619169658404581055569343649552237459405389619878622595233883088117550243589990766295123312113223283666311520867475139053092710762637855713671921562262375388239616545168599659887895366565464743090393090917526710854631822434014024

bits = bin(ACC)[2:]
parity_bits = bits[1:]  # drop leading 1

n = 1
for b in parity_bits[::-1]:
    if b == '0':
        n = n * 2
    else:
        n = (2 * n - 1) // 3

flag_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
print(flag_bytes.decode())
```

## Flag

```
lactf{7h3r3_m4y_83_50m3_155u35_w17h_7h15_1f_7h3_c011472_c0nj3c7ur3_15_d15pr0v3n}
```
