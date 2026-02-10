# not-so-lazy-trigrams (crypto)

## Challenge summary
The provided `chall.py` does the following:
1. Reads a plaintext (`pt.txt`), strips non-letters, lowercases it.
2. Pads with `x` so the length is a multiple of 3.
3. Encrypts each trigram by applying a substitution table built from
   three independent shuffles of the alphabet (one for each trigram
   position).
4. Re-inserts the original punctuation/formatting with a formatter.

The output `ct.txt` is given, and the flag format is `lactf{...}`.

## Key observations
- The trigram substitution is **not** a single permutation over all 26^3
  trigrams. Instead, it is the Cartesian product of three monoalphabetic
  substitutions, one for each position modulo 3.
- This means encryption is equivalent to **three independent substitution
  ciphers** applied to the letter stream, depending on index mod 3.
- Punctuation is preserved, so the ciphertext still contains the literal
  `{` and `}` from the flag.

## Attack idea
1. Strip punctuation and solve the three interleaved monoalphabetic
   substitutions with a standard substitution-cipher hillclimb.
2. Use a quadgram log-likelihood score to guide simulated annealing.
3. Apply a crib from the flag:
   - Because `{` is preserved, the five letters before `{` must be `lactf`.
   - The clean-letter index of those letters gives exact constraints on
     which substitution (mod 3) maps those ciphertext letters to `l`, `a`,
     `c`, `t`, `f`.

With those constraints, hillclimbing converges quickly.

## Solution outline
1. Read `ct.txt` and build `clean = letters_only(ct).lower()`.
2. Compute the clean-letter index of the five letters before `{`.
   - Let `i` be the clean index of a letter, then its key is `i % 3`.
   - Fix the mappings for those letters to match `lactf`.
3. Build a quadgram scorer from a local English corpus.
4. Simulated annealing:
   - Maintain three 26-letter permutations (one per mod-3 position).
   - Swap two entries in one permutation and accept/reject by score.
5. Reconstruct the plaintext with punctuation and read the flag.

## Result
Recovered flag:

```
lactf{still_too_lazy_to_write_a_plaintext_so_heres_a_random_wikipedia_article}
```

## Notes
- The recovered plaintext is a snippet about circular polarization, which
  is a realistic English passage and validates the decryption.
- The key insight is that the trigram substitution is separable into three
  monoalphabetic substitutions rather than a full 26^3 substitution.
