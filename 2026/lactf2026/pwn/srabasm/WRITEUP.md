# ScrabASM (pwn)

## Challenge summary
The program deals a 14-byte "hand" and lets you swap any tile. When you press play, those 14 bytes are copied to an RWX page at a fixed address and executed as code. Tiles are generated with `rand()` seeded by `time(NULL)`.

Key facts:
- Hand size: 14 bytes
- Board address: `0x13370000`
- Board is RWX and the hand bytes are executed directly
- Swapping a tile calls `rand()` again and replaces a chosen index with `rand() & 0xff`

## Vulnerability
The program executes user-controlled bytes without validation (a classic "execute arbitrary bytes" bug). The only constraint is that the initial bytes are random, and each swap gives a fresh `rand() & 0xff` for a selected index.

Because the PRNG is `rand()` seeded by `time(NULL)`, the entire sequence of bytes is predictable once the seed is recovered from the printed starting hand.

## Exploit strategy
1. **Recover PRNG seed** by matching the 14 printed bytes to `rand() & 0xff` for seeds around current time.
2. **Plan swaps**: after 14 `rand()` calls (initial hand), keep consuming `rand()` and assign each output to a swap index. We wait until the desired byte for each position appears, then swap that index at that moment.
3. **Stage1 shellcode (14 bytes)**: a tiny read stub that loads stage2 into the board and jumps there.
4. **Stage2 shellcode**: a standard `/bin/sh` payload.

### Stage1 (14 bytes)
This stub reads up to 0x80 bytes from stdin into `rsi` (which already points to the board) and jumps to it:

```
48 96                      xchg rsi, rax
31 ff                      xor edi, edi
31 d2                      xor edx, edx
b2 80                      mov dl, 0x80
31 c0                      xor eax, eax
0f 05                      syscall
ff e6                      jmp rsi
```

We prepend 12 NOPs to stage2 so execution can safely land at offset 12 if the read overwrites the currently executing bytes.

## Exploit implementation
The solver:
- Parses the initial hand from the banner.
- Finds the seed in a time window (default 24 hours).
- Simulates `rand()` to compute the exact swap order for the target 14 bytes.
- Sends all menu inputs in one batch to avoid network RTT delay.
- Sends stage2 shellcode and spawns a shell.

File: `solve.py`

Example run:
```
python3 solve.py REMOTE=1
```

## Flag
```
lactf{gg_y0u_sp3ll3d_sh3llc0d3}
```
