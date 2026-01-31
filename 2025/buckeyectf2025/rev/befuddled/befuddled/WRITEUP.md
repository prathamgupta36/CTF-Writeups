# BuckeyeCTF 2025 – rev/befuddled (Writeup)

Flag: `bctf{c0mPIle_Th3_unC0mp1labl3}`

## TL;DR
- The binary embeds and runs a Befunge‑93 program.
- We load that exact grid from the ELF and execute it under a deterministic interpreter.
- A simple greedy heuristic (choose the next character that maximizes the number of conditional “gate” events before halting) reconstructs the full flag from right to left.
- Verified by running the actual binary: it prints “Correct!!!”.

## Challenge Summary
- Category: Reversing
- Prompt: “We got this binary from another dimension… Enter flag…”
- Binary: `befuddled` (ELF x86‑64, stripped)

## Recon and Observations
- Basic info:
  - `file befuddled` → 64‑bit ELF, dynamically linked, stripped
  - `strings befuddled` reveals:
    - `"Enter the flag: "`
    - `"NOPE!!!!!!"`
    - `"Correct!!!"`
- The program prompts and either rejects or accepts based on the input, typical of verifier puzzles.

## Embedded Befunge Program
- The core logic lives in a Befunge‑93 program embedded in the binary’s data section.
- We can extract this grid and run it directly using a small Befunge interpreter.
  - Interpreter used: `befunge_runner.py`
  - Loading the grid from the binary: `load_program_from_binary('befuddled', 0x8038, 0x52, 25)`
  - A readable dump of the program is included as `program.bf` (80×25). It clearly contains the prompt, the `NOPE!!!!!!` and `Correct!!!` strings, plus a labyrinth of conditionals (`|` and `_`).

## Befunge Semantics (the bits we need)
- Befunge executes on a 2D grid with an instruction pointer moving in a direction.
- The verifier uses:
  - `~` to read input bytes
  - `|` (vertical if): pop a value; go up if nonzero, down if zero (or vice‑versa depending on implementation)
  - `_` (horizontal if): pop a value; go left if nonzero, right if zero
  - arithmetic/stack ops to compute those popped values from the input
- Therefore, each “gate” (`|`/`_`) consumes a number and branches based on whether it’s zero.

## Strategy: Instrument Gates, Then Greedy Longest‑Path Search
- We run the exact grid and record a sequence of gate events: for each `|`/`_`, its coordinate and the value popped.
- Intuition: the correct character at the next position (moving right→left inside the braces) tends to allow the instruction pointer to traverse more gates before ultimately reaching `Correct!!!`. A wrong char typically causes an earlier branch into a “NOPE” path.
- Heuristic: for the next unknown character, try all printable ASCII and pick the one that maximizes the number of gate events before halting. Prepend it to the suffix and repeat.
- This worked cleanly here and quickly converged on the full flag.

## Implementation Notes
- Runner: `befunge_runner.py`
  - Loads from the binary and runs deterministically; returns output, status, and additional trace/debug info when needed.
- Grid: `program.bf`
  - Human‑readable 80×25 dump of the embedded program.
- Instrumentation helper: `solver.py`
  - Contains `event_seq(...)` which executes the grid with a given input and returns the list of `('|', (x,y), value)` / `('_', (x,y), value)` events.
- Greedy reconstruction (concept):
  1. Let `S` be the known suffix (start empty).
  2. For each printable ASCII `c`, evaluate `event_seq(c + S)`, measure the length.
  3. Choose the `c` with the maximum length; set `S = c + S`.
  4. After each step, test `bctf{S}\n` against the VM; stop when it prints `Correct!!!`.

## Results
- The greedy procedure produced (from right to left):
  - `c0mPIle_Th3_unC0mp1labl3`
- Full flag: `bctf{c0mPIle_Th3_unC0mp1labl3}`

## Verification
- Using the embedded grid runner:
  - Input: `bctf{c0mPIle_Th3_unC0mp1labl3}\n`
  - Output: `Enter the flag: Correct!!!`
- Using the provided binary:
  - `./befuddled <<< 'bctf{c0mPIle_Th3_unC0mp1labl3}'`
  - Output: `Enter the flag: Correct!!!`

## Reproduce Locally
- Quick check with the binary:
  - `./befuddled <<< 'bctf{c0mPIle_Th3_unC0mp1labl3}'`
- Run with the interpreter (from the extracted grid):
  - `python3 befunge_runner.py program.bf -i 'bctf{c0mPIle_Th3_unC0mp1labl3}\n'`

## Why This Works
- The Befunge program is structured as a series of conditional gates that compute values derived from successive input characters.
- The “correct path” is simply longer and passes through many more gates before reaching `Correct!!!`. Wrong characters fork to shorter paths that end in `NOPE!!!!!!` sooner.
- Measuring the number of gate events acts as a discriminant for correct vs. incorrect character choices, allowing a greedy reconstruction from the end of the flag toward the beginning.

## Notes
- A more algebraic approach (solving for each gate’s exact linear relation to the next character via A/B differentials) also works but is unnecessary here given how cleanly the longest‑path heuristic separates correct characters.
- The offset/size used to extract the grid are specific to this binary build (`0x8038`, width `0x52`, height `25`).

