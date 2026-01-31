# Gambler's Fallacy - uoftctf 2026 Crypto Challenge

## Challenge Overview
- Category: Crypto
- Points / Solves: 451 pts / 3 solves
- To Do: Play a primedice-inspired gambling game (`nc 34.162.20.138 5000`) and buy the $10,000 flag.
- Files provided: `chall.py`, `serverseed`, Docker harness.

Running the service locally reveals a dice game that resembles real-world provably fair gambling sites. We start with a \$800 balance and can change our client seed, but every wager reveals the *server seed* used for that roll. The server promises fairness by hashing the deterministic combination of:
```
roll = HMAC_SHA256(key=str(server_seed), msg=f"{client_seed}-{nonce}")
```
The bug is that `server_seed` itself is produced by Python's `random.getrandbits(32)` seeded with the file `serverseed`. Since Python's PRNG is the Mersenne Twister (MT19937), learning 624 consecutive outputs is enough to reconstruct its internal state and predict every future roll.

## Vulnerability Analysis
1. Initialization - `random.seed(open("serverseed").read())` sets a deterministic MT19937 state.
2. Observable outputs - Every game loop logs `Server-Seed: {self.server_seed}` before the HMAC is evaluated. The entire 32-bit MT output is leaked per roll.
3. State recovery - MT19937 outputs are tempered 32-bit words. By inverting the tempering function ("untwisting"), we can recover the raw state value corresponding to each output.
4. Full state reconstruction - Collect 624 server seeds (the size of the MT state array). Untemper each, set the recovered state into our own `random.Random` instance, and we can call `getrandbits(32)` to obtain the same numbers as the server for all future rolls.
5. Roll prediction - With the predicted `server_seed`, replicate the game's `compute_roll` HMAC logic to know the exact dice outcome before betting.

This setup mirrors the "provably fair" casino pattern: the HMAC prevents tampering with past rolls, but leaking the RNG output entirely destroys the unpredictability requirement.

## Exploit Strategy
1. Harvest MT outputs - Run 624 minimal wagers (`wager=1`, `greed=98`) to dump 624 server seeds into our client.
2. Untemper + seed local MT - Apply the inverse tempering transforms to each leaked seed and load them into a `random.Random` instance via `setstate`.
3. Predict and bet - For each future game:
   - Pull the next MT output locally.
   - Derive the roll via the same HMAC logic (client seed and nonce are known).
   - If the prediction is a guaranteed win (roll ≤ chosen greed), wager the entire balance. Otherwise, "burn" the prediction with a $1 bet to keep our MT state synchronized without risking the bankroll.
4. Reach $10,000 - Repeat until the balance clears the shop price, then buy the flag.

### Why the burn bet works
MT19937 is purely deterministic, so we cannot skip outputs. When we predict a losing roll we must still submit an actual wager so that the server consumes the same RNG value. Using the minimum stake loses only $1 in those rounds while keeping our prediction window aligned.

## Implementation Notes (`solve.py`)
- MT Untempering: `undo_right_shift_xor` / `undo_left_shift_xor_mask` reverse Python's MT tempering to recover raw state values.
- State Loader: `RandCrack.submit()` rebuilds the MT state once 624 values are collected.
- Game harness: `GameClient` simulates menu interactions, parses balances, and captures the server seed from each log line.
- Prediction loop: After `gather_state`, the script continuously predicts the next roll; safe bets stake the full balance, while bad rolls use a $1 burn.
- Flag retrieval: Upon surpassing $10,000, the script navigates the shop and prints the flag.

## Reproduction Steps
1. Install dependencies (pwntools):
   ```bash
   pip install --user --break-system-packages pwntools
   ```
2. Run the solver:
   ```bash
   python3 solve.py
   ```
3. The script will harvest RNG outputs, predict profitable bets, and output the flag. Testing locally (`python3 solve.py local`) prints the placeholder `uoftctf{fake_flag}`; the remote service returns the real flag `uoftctf{ez_m3rs3nne_untwisting!!}`.

## Lessons Learned
- Revealing raw PRNG outputs instantly kills "provable fairness." Mixing a cryptographic hash with predictable entropy provides zero security.
- MT19937 remains popular but is unsuitable for security-critical randomness; state recovery is well-documented and automated.
- Always treat deterministic RNG outputs as secrets. Even 32-bit leaks are enough to recover MT state with standard tooling like RandCrack.
