# lazy-bigrams (crypto)

## Challenge summary
The provided `chall.py` does the following:
1. Takes the flag and applies a *phonetic mapping* (NATO alphabet + words for digits, `{`, `}`, `_`).
2. Applies the same phonetic mapping again to the result.
3. Splits the final text into bigrams (two-letter blocks) and applies a random permutation of the 26×26 bigrams.

Only the ciphertext `ct.txt` is given. The flag is lowercase.

The key observation: the final plaintext is letters only (A–Z), because the second phonetic mapping only uses words made of letters. Therefore the ciphertext is a bigram substitution cipher on A–Z bigrams.

## Key ideas
- Let the final plaintext be a sequence of A–Z letters. The encryption is a bijection on bigrams: each ciphertext bigram corresponds to exactly one plaintext bigram, and vice versa.
- The plaintext is *not arbitrary letters*: it must be a concatenation of the NATO words (ALPHA, BRAVO, ..., ZULU), with an optional trailing padding `X` added if the length is odd at either mapping step.
- This can be modeled as a constraint satisfaction problem:
  - Variables for each ciphertext bigram's two plaintext letters.
  - All 26×26 plaintext bigrams must be distinct (injective mapping).
  - The resulting plaintext letter sequence must be accepted by a DFA that recognizes “concatenation of NATO words, with optional trailing X padding”.

## Solving approach
1. Build a DFA for the language:
   - Words are the NATO alphabet words for A–Z.
   - From the boundary state, you can start any word.
   - Optional padding `X` is allowed at the end.
2. Create a CP-SAT model:
   - For each ciphertext bigram `C`, create two variables `(C0, C1)` in `0..25`.
   - For every position in the ciphertext, set the plaintext letter to `C0` or `C1` depending on the bigram slot.
   - Enforce `AllDifferent(26*C0 + C1)` across all ciphertext bigrams (bigram permutation).
   - Add the DFA constraint over the full plaintext letter sequence.
3. Solve with CP-SAT (OR-Tools).
4. Decode the resulting plaintext:
   - Segment the plaintext letters into NATO words to recover the first phonetic mapping.
   - Then segment those words into the full phonetic map (including digits and braces) to recover the flag.

## Result
The recovered flag is:

```
lactf{n0t_r34lly_4_b1gr4m_su8st1tu7ion_bu7_1_w1ll_tak3_1t_f0r_n0w}
```

## Notes
- This solution avoids guessing the substitution by hand and treats the text grammar (NATO words) as a strict constraint.
- Any SAT/CP solver that supports automaton constraints or equivalent regular-language constraints works.
