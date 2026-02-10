## The Three-SAT Problem (rev)

### Overview
The binary asks for a 1279-byte string and checks it with a huge straight-line
bitwise circuit. If the circuit evaluates to true and a specific input bit is
set, the program prints the flag.

### Quick Recon
- `three_sat_problem` is a stripped 64-bit ELF.
- It prints a prompt, reads up to `0x500` bytes, strips the newline, and
  requires the length to be exactly `0x4ff` (1279).
- It rejects any character that is not `'0'` or `'1'`.

Disassembly highlights:
- Input buffer base: `0x15060` (in .data).
- There is a check `testb $0x1, 0x15352`, which is `0x15060 + 0x2f2`, so it
  forces input byte `inp[0x2f2]` to have LSB = 1 (`'1'`).
- The main logic is a function at `0x1289` that:
  - Loads bits from many places (input bytes and constants).
  - Applies a massive combination of `NOT`, `AND`, and `OR`.
  - Returns a boolean in `AL` (true => success).
- No branches appear in this block; it is purely straight-line logic (i.e.,
  a large SAT circuit).

### Core Insight
Since the logic is straight-line bitwise ops over 1-byte and 4-byte values,
it can be symbolically executed. The output is a single bit (AL != 0), so we
can set up a solver with:
- each input byte constrained to `'0'` or `'1'`;
- `inp[0x2f2] == '1'`;
- final `AL != 0`.

### Solving Strategy
1. Disassemble the straight-line block with Capstone.
2. Emulate it symbolically with Z3:
   - Treat the 1279 input bytes as 8-bit BitVecs.
   - Model registers and memory as bitvectors.
   - Execute `mov`, `and`, `or`, `xor`, `not`, `add`, `sub`, `push`, `pop`.
3. Ask Z3 for any satisfying assignment.
4. The binary uses a 0x140-entry table in `.rodata` to map input bits into a
   0x28-byte output buffer, which it prints as a C string. Reconstruct it by
   applying the same mapping to the solved input.

### Result
The solver finds a valid 1279-bit assignment. When mapped and printed, it
produces the flag:

```
lactf{is_the_three_body_problem_np_hard}
```

### Flag
`lactf{is_the_three_body_problem_np_hard}`
