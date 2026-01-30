# Orca (UofTCTF) Writeup

## Challenge
- Name: Orca
- Points: 477
- Author: SteakEnthusiast
- Description: Orcas eat squids :(
- Service: `nc 34.186.247.84 5000`

## Files
- `src/server.py`
- `src/flag.txt` (local fake flag)
- `solve.py` (solver)

## Summary
The service encrypts a message containing a random-length prefix, our input, and the flag using AES-ECB, then permutes ciphertext blocks and returns only a single block by index. The permutation is fixed for the process, and the prefix length is fixed but unknown. By sending multiple queries and checking which block indices remain stable across repeated encryptions, we can identify the block index we control and recover the flag with a byte-at-a-time ECB attack. We also map the permutation to translate logical block numbers to returned indices.

## Server Behavior (from `src/server.py`)
Key points:
- `pl` is a random prefix length in `[0, 96]` (one byte, mod 97).
- For each query, it builds:
  ```
  m = random_prefix(pl bytes) || user_input (capped to 256 bytes) || FLAG
  ```
- The message is truncated/padded to L = 1024 bytes and then AES-ECB encrypted.
- The ciphertext is split into 16-byte blocks and permutes them with a fixed random permutation `q`.
- The server returns one permuted block at a user-chosen index.

This is a classic ECB oracle (with a hidden suffix) but with two obstacles:
1) Unknown random prefix length
2) Shuffled blocks

Both are fixed per process, so we can learn them.

## Core Idea
Even though each request uses fresh random prefix bytes, the permutation and the prefix length stay constant. If we repeat the same query multiple times and look at which ciphertext indices are identical across all repetitions, those blocks are the ones that do not include random bytes. That lets us locate stable blocks and identify the first block fully controlled by our input.

With alignment solved and permutation learned, we can perform a standard byte-at-a-time ECB attack to recover the appended flag.

## Step 1 — Find Alignment (Prefix Length Mod 16)
We need to find a padding length `pad` such that:
```
(prefix length + pad) % 16 == 0
```
We brute-force `pad = 0..15` and send two payloads:
- `A * (pad + 16)`
- `A * pad + B + A * 15`

For each payload, we repeat the query several times and only keep block indices that are stable across repetitions. The index where the two payloads differ (but are stable) is the first block fully controlled by our input.

In `solve.py`, this is implemented in:
- `get_stable(...)`
- `find_alignment(...)`

## Step 2 — Map Permutation (Logical Block → Returned Index)
We need to know which returned index corresponds to our logical block `k` so the byte-at-a-time dictionary attack compares the right ciphertext blocks.

We do this by constructing a payload with distinct full blocks:
```
block0 = 0x00 * 16
block1 = 0x01 * 16
block2 = 0x02 * 16
...
```
Then we flip only block `k` (replace it with another constant) and find which stable ciphertext index changes. That index is the permuted position of logical block `k`.

Implemented in:
- `map_block(...)`

## Step 3 — Byte-at-a-Time ECB
Once we know the index for each logical block, we can recover the flag one byte at a time:
1) Craft a prefix so the unknown byte is the last byte of a block.
2) Query the target block for that prefix.
3) Build a dictionary by trying all candidate bytes and matching ciphertext blocks.
4) Append the matched byte to the recovered flag and repeat.

We limit the brute-force alphabet to printable ASCII to reduce queries.

Implemented in:
- `recover_flag(...)`

## Solver (`solve.py`) Overview
- `RemoteOracle`: handles the network protocol with the prompt.
- `LocalOracle`: loads the local `src/server.py` for testing.
- `get_stable`: repeated queries to identify stable indices.
- `find_alignment`: find padding and first controlled block index.
- `map_block`: map block numbers to permuted indices.
- `recover_flag`: ECB byte-at-a-time flag recovery.

## Running the Solver
Local (fake flag):
```bash
python3 solve.py
```
Remote:
```bash
python3 solve.py --remote
```

## Flag
Recovered from the remote service:
```
uoftctf{l37_17_b3_kn0wn_th4t_th3_0r4c13_h45_5p0k3N_ac9ae43a889d2461fa7039201b6a1a75}
```

## Why This Works
- ECB encryption is deterministic per block, so identical plaintext blocks yield identical ciphertext blocks.
- The random prefix bytes only affect the early blocks; any fully-controlled block becomes stable.
- The permutation does not change, so mapping it once is enough to index the correct blocks.
- Classic ECB byte-at-a-time recovery works as long as we can compare the correct target block.

## Notes
- The solver can take several minutes remotely due to many queries.
- The stability checks handle the randomness without needing to know the actual prefix length.
- The `max_len` in the solver can be increased if needed.
