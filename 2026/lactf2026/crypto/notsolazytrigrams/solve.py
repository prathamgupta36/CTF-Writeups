#!/usr/bin/env python3
import math
import os
import random
import re
from collections import Counter

def build_quadgram_scorer(corpus_text: str):
    corpus_text = re.sub(r"[^a-zA-Z]", "", corpus_text).lower()
    if len(corpus_text) < 1000:
        raise ValueError("Corpus too small for quadgram scoring")
    counts = Counter(corpus_text[i:i+4] for i in range(len(corpus_text) - 3))
    total = sum(counts.values())
    logp = {k: math.log10(v / total) for k, v in counts.items()}
    # floor for unseen quadgrams
    log_floor = math.log10(0.01 / total)
    return logp, log_floor


def load_corpus():
    # Prefer a reasonably large local English corpus.
    candidates = [
        "/usr/share/doc/aptitude/README",
        "/usr/share/common-licenses/GPL-3",
        "/usr/share/common-licenses/GPL-2",
    ]
    texts = []
    for path in candidates:
        if os.path.exists(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    texts.append(f.read())
            except OSError:
                pass
    if texts:
        return "\n".join(texts)
    # Fallback: a small built-in corpus (not great, but better than nothing).
    return (
        "this is a fallback english corpus used for scoring quadgrams. "
        "it is not large, but it contains common words and letter patterns. "
        "substitution ciphers are usually solved with ngram statistics. "
        "the quick brown fox jumps over the lazy dog multiple times. "
    )


def clean_letters(s: str) -> str:
    return re.sub(r"[^a-zA-Z]", "", s).lower()


def build_constraints_from_flag_prefix(ct: str, prefix: str = "lactf"):
    # The ciphertext preserves punctuation. Find "{" and take the five
    # letters immediately before it in the original text.
    idx = ct.index("{")
    constraints = [dict(), dict(), dict()]  # per position mod 3: cipher -> plain
    for k, plain_ch in enumerate(prefix):
        i = idx - len(prefix) + k
        cipher_ch = ct[i].lower()
        clean_index = sum(1 for c in ct[:i] if c.isalpha())
        pos = clean_index % 3
        constraints[pos][ord(cipher_ch) - 97] = ord(plain_ch) - 97
    return constraints


def solve(ct: str, restarts: int = 6, steps: int = 30000, seed: int = 2):
    clean = clean_letters(ct)
    C = [ord(ch) - 97 for ch in clean]
    n = len(C)

    logp, log_floor = build_quadgram_scorer(load_corpus())

    constraints = build_constraints_from_flag_prefix(ct, "lactf")

    # Precompute positions for each (pos, cipher_letter)
    positions = [[[ ] for _ in range(26)] for _ in range(3)]
    for i, c in enumerate(C):
        positions[i % 3][c].append(i)

    letters = list(range(26))

    def random_key_for_pos(pos):
        fixed = constraints[pos]
        mapping = [None] * 26
        used_plain = set()
        used_cipher = set()
        for c, p in fixed.items():
            mapping[c] = p
            used_plain.add(p)
            used_cipher.add(c)
        remaining_plain = [i for i in letters if i not in used_plain]
        remaining_cipher = [i for i in letters if i not in used_cipher]
        random.shuffle(remaining_plain)
        for ci, pi in zip(remaining_cipher, remaining_plain):
            mapping[ci] = pi
        return mapping

    alphabet = "abcdefghijklmnopqrstuvwxyz"

    def quad_score_at(P, i):
        quad = ''.join(alphabet[P[i + j]] for j in range(4))
        return logp.get(quad, log_floor)

    # Initialize keys and plaintext
    key = [random_key_for_pos(0), random_key_for_pos(1), random_key_for_pos(2)]
    P = [0] * n
    for i, c in enumerate(C):
        P[i] = key[i % 3][c]

    cur_score = sum(quad_score_at(P, i) for i in range(n - 3))
    best_score = cur_score
    best_key = [k[:] for k in key]

    nonfixed = [[c for c in letters if c not in constraints[pos]] for pos in range(3)]

    random.seed(seed)
    for restart in range(restarts):
        if restart > 0:
            key = [random_key_for_pos(0), random_key_for_pos(1), random_key_for_pos(2)]
            for i, c in enumerate(C):
                P[i] = key[i % 3][c]
            cur_score = sum(quad_score_at(P, i) for i in range(n - 3))

        T = 6.0
        cooling = 0.9992

        for _ in range(steps):
            pos = random.randrange(3)
            a, b = random.sample(nonfixed[pos], 2)

            idxs = positions[pos][a] + positions[pos][b]
            if not idxs:
                continue

            affected = set()
            for i in idxs:
                for j in range(i - 3, i + 1):
                    if 0 <= j <= n - 4:
                        affected.add(j)

            old = sum(quad_score_at(P, j) for j in affected)

            # swap mapping entries
            key[pos][a], key[pos][b] = key[pos][b], key[pos][a]
            for i in positions[pos][a]:
                P[i] = key[pos][a]
            for i in positions[pos][b]:
                P[i] = key[pos][b]

            new = sum(quad_score_at(P, j) for j in affected)
            new_score = cur_score - old + new

            if new_score > cur_score or random.random() < math.exp((new_score - cur_score) / T):
                cur_score = new_score
                if cur_score > best_score:
                    best_score = cur_score
                    best_key = [k[:] for k in key]
            else:
                # revert swap
                key[pos][a], key[pos][b] = key[pos][b], key[pos][a]
                for i in positions[pos][a]:
                    P[i] = key[pos][a]
                for i in positions[pos][b]:
                    P[i] = key[pos][b]

            T *= cooling

    # Decode with best key
    key = best_key
    for i, c in enumerate(C):
        P[i] = key[i % 3][c]
    plain_letters = ''.join(alphabet[p] for p in P)

    # Reinsert punctuation
    res = []
    li = 0
    for ch in ct:
        if ch.isalpha():
            res.append(plain_letters[li])
            li += 1
        else:
            res.append(ch)
    return ''.join(res)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Solve not-so-lazy-trigrams")
    parser.add_argument("ct", nargs="?", default="ct.txt", help="ciphertext file")
    args = parser.parse_args()

    with open(args.ct, "r") as f:
        ct = f.read().strip()

    pt = solve(ct)
    m = re.search(r"lactf\{[^}]+\}", pt)
    if m:
        print(m.group(0))
    else:
        print("[!] flag not found")
        print(pt[:500])


if __name__ == "__main__":
    main()
