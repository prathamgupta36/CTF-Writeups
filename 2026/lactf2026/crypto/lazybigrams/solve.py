#!/usr/bin/env python3
import re
from collections import deque, defaultdict

try:
    from ortools.sat.python import cp_model
except Exception as e:
    raise SystemExit(
        "ortools is required. Install with:\n"
        "  python3 -m venv /tmp/venv-ortools\n"
        "  /tmp/venv-ortools/bin/pip install ortools\n"
        "  /tmp/venv-ortools/bin/python solve.py\n"
    ) from e


LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LETTER_IDX = {c: i for i, c in enumerate(LETTERS)}

PHONETIC_MAP = {
    "A": "ALPHA",
    "B": "BRAVO",
    "C": "CHARLIE",
    "D": "DELTA",
    "E": "ECHO",
    "F": "FOXTROT",
    "G": "GOLF",
    "H": "HOTEL",
    "I": "INDIA",
    "J": "JULIETT",
    "K": "KILO",
    "L": "LIMA",
    "M": "MIKE",
    "N": "NOVEMBER",
    "O": "OSCAR",
    "P": "PAPA",
    "Q": "QUEBEC",
    "R": "ROMEO",
    "S": "SIERRA",
    "T": "TANGO",
    "U": "UNIFORM",
    "V": "VICTOR",
    "W": "WHISKEY",
    "X": "XRAY",
    "Y": "YANKEE",
    "Z": "ZULU",
    "_": "UNDERSCORE",
    "{": "OPENCURLYBRACE",
    "}": "CLOSECURLYBRACE",
    "0": "ZERO",
    "1": "ONE",
    "2": "TWO",
    "3": "THREE",
    "4": "FOUR",
    "5": "FIVE",
    "6": "SIX",
    "7": "SEVEN",
    "8": "EIGHT",
    "9": "NINE",
}


def build_dfa():
    """DFA for concatenation of NATO words with optional trailing X padding."""
    words = [v for k, v in PHONETIC_MAP.items() if k.isalpha()]
    # NFA states: 0=boundary, 1=padding, others are word positions.
    state_id = {}
    states = [("B", 0), ("P", 0)]
    for w in words:
        for pos in range(1, len(w)):
            state_id[(w, pos)] = len(states)
            states.append((w, pos))
    s_count = len(states)
    b_state = 0
    p_state = 1
    nfa_trans = [[set() for _ in range(s_count)] for _ in range(26)]

    # Transitions from boundary to word start.
    for w in words:
        li = LETTER_IDX[w[0]]
        nxt = b_state if len(w) == 1 else state_id[(w, 1)]
        nfa_trans[li][b_state].add(nxt)

    # Optional padding 'X' after boundary.
    li_x = LETTER_IDX["X"]
    nfa_trans[li_x][b_state].add(p_state)

    # Internal word transitions.
    for w in words:
        for pos in range(1, len(w)):
            state = state_id[(w, pos)]
            li = LETTER_IDX[w[pos]]
            nxt = b_state if pos + 1 == len(w) else state_id[(w, pos + 1)]
            nfa_trans[li][state].add(nxt)

    # Determinize to DFA.
    start = frozenset([b_state])
    queue = deque([start])
    state_map = {start: 0}
    accepting = set()
    dfa_trans = []

    while queue:
        sset = queue.popleft()
        idx = state_map[sset]
        if idx >= len(dfa_trans):
            dfa_trans.append([None] * 26)
        if b_state in sset or p_state in sset:
            accepting.add(idx)
        for li in range(26):
            next_set = set()
            for s in sset:
                next_set.update(nfa_trans[li][s])
            if not next_set:
                continue
            next_set = frozenset(next_set)
            if next_set not in state_map:
                state_map[next_set] = len(state_map)
                queue.append(next_set)
            dfa_trans[idx][li] = state_map[next_set]

    num_states = len(state_map)
    dead = num_states
    num_states += 1
    transitions = []
    for s in range(num_states):
        for li in range(26):
            if s == dead:
                transitions.append((dead, li, dead))
            else:
                ns = dfa_trans[s][li]
                transitions.append((s, li, dead if ns is None else ns))
    return accepting, transitions


def segment_words(text, word_map):
    """DP segmentation into known words (maximizes matched length)."""
    words_by_len = defaultdict(list)
    for w in word_map:
        words_by_len[len(w)].append(w)

    n = len(text)
    dp = [-10**9] * (n + 1)
    dp[n] = 0
    nxt = [None] * (n + 1)
    for i in range(n - 1, -1, -1):
        best = dp[i + 1] - 1
        bestw = None
        for l, ws in words_by_len.items():
            if i + l <= n:
                seg = text[i : i + l]
                if seg in ws:
                    val = dp[i + l] + l
                    if val > best:
                        best = val
                        bestw = seg
        dp[i] = best
        nxt[i] = bestw

    segs = []
    i = 0
    while i < n:
        w = nxt[i]
        if w is None:
            segs.append(text[i])
            i += 1
        else:
            segs.append(w)
            i += len(w)
    return segs


def main():
    with open("ct.txt", "r", encoding="ascii") as f:
        ct = f.read().strip()

    blocks = [ct[i : i + 2] for i in range(0, len(ct), 2)]
    unique_blocks = sorted(set(blocks))
    n_blocks = len(unique_blocks)
    L = len(ct)

    accepting, transitions = build_dfa()

    model = cp_model.CpModel()

    bigram_index = {b: i for i, b in enumerate(unique_blocks)}
    b0 = [model.NewIntVar(0, 25, f"b0_{i}") for i in range(n_blocks)]
    b1 = [model.NewIntVar(0, 25, f"b1_{i}") for i in range(n_blocks)]

    x = [model.NewIntVar(0, 25, f"x_{i}") for i in range(L)]
    for i in range(L):
        bi = bigram_index[blocks[i // 2]]
        if i % 2 == 0:
            model.Add(x[i] == b0[bi])
        else:
            model.Add(x[i] == b1[bi])

    # Enforce bijection on bigrams.
    pairs = [model.NewIntVar(0, 26 * 26 - 1, f"p_{i}") for i in range(n_blocks)]
    for i in range(n_blocks):
        model.Add(pairs[i] == b0[i] * 26 + b1[i])
    model.AddAllDifferent(pairs)

    # Regular language constraint on plaintext letters.
    model.AddAutomaton(x, 0, list(accepting), transitions)

    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = 60.0
    solver.parameters.num_search_workers = 8
    res = solver.Solve(model)
    if res not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        raise SystemExit("No solution found.")

    plaintext = "".join(LETTERS[solver.Value(v)] for v in x)

    # First-level decoding: A-Z NATO words.
    letters_words = {v: k for k, v in PHONETIC_MAP.items() if k.isalpha()}
    segs = segment_words(plaintext, letters_words)
    letters_seq = "".join(letters_words[s] for s in segs if s in letters_words)

    # Second-level decoding: full phonetic map (digits, braces, underscore).
    full_words = {v: k for k, v in PHONETIC_MAP.items()}
    segs2 = segment_words(letters_seq, full_words)
    flag_chars = [full_words[s] for s in segs2 if s in full_words]
    flag = "".join(flag_chars).lower()
    print(flag)


if __name__ == "__main__":
    main()
