#!/usr/bin/env python3

"""
Square Cipher Solver

Builds the 9x9 nibble constraints from the challenge constants, solves for
the nibble popcounts (each nibble’s bitcount), constructs a valid hex input x,
validates locally, and can optionally submit to the remote.

Usage:
  python3 solver.py            # print hex solution
  python3 solver.py --verify   # also verify constraints locally
  python3 solver.py --grid     # print 9x9 grid of nibble popcounts
  python3 solver.py --submit   # connect to remote and print response
"""

from __future__ import annotations

import argparse
import socket
import ssl
from typing import List, Tuple


# Constants extracted from square_cipher.py
A = 2135465562637171390290201561322170738230609084732268110734985633502584038857972308065155558608880
B = 1271371190459412480076309932821732439054921890752535035282222258816851982409101952239053178406432
YS = [
    511, 261632, 1838599, 14708792, 117670336, 133955584, 68585259008, 35115652612096,
    246772580483072, 1974180643864576, 15793445150916608, 17979214137393152, 9205357638345293824,
    4713143110832790437888, 4731607904558235517441, 9463215809116471034882,
    18926431618232942069764, 33121255085135066300416, 37852863236465884139528,
    75705726472931768279056, 151411452945863536558112, 264970040681080530403328,
    302822905891727073116224, 605645811783454146232448, 1211291623566908292464896,
    2119760325448644243226624, 2413129272746388704198656,
]


def build_groups(ys: List[int]) -> List[List[int]]:
    rows: List[List[int] | None] = [None] * 9
    cols: List[List[int] | None] = [None] * 9
    boxes: List[List[int]] = []
    for y in ys:
        g = [i for i in range(y.bit_length()) if (y >> i) & 1]
        if g == list(range(g[0], g[0] + 9)):
            rows[g[0] // 9] = g
        elif all((g[i + 1] - g[i] == 9) for i in range(8)):
            cols[g[0] % 9] = g
        else:
            boxes.append(g)
    assert all(r is not None for r in rows)
    assert all(c is not None for c in cols)
    return [r for r in rows if r is not None] + [c for c in cols if c is not None] + boxes


def derive_domains(A: int, B: int, cells: int = 81) -> Tuple[List[Tuple[int, int]], List[int], List[int], List[int]]:
    forced_one = [0] * cells
    free_bits = [4] * cells
    forced_one_mask = [0] * cells
    forced_zero_mask = [0] * cells
    for i in range(cells):
        for b in range(4):
            bitpos = 4 * i + b
            if (A >> bitpos) & 1:
                free_bits[i] -= 1
                if (B >> bitpos) & 1:
                    forced_one[i] += 1
                    forced_one_mask[i] |= (1 << b)
                else:
                    forced_zero_mask[i] |= (1 << b)
    domain = [(forced_one[i], forced_one[i] + free_bits[i]) for i in range(cells)]
    return domain, forced_one, forced_one_mask, forced_zero_mask


def solve_popcounts(groups: List[List[int]], domain: List[Tuple[int, int]]) -> List[int]:
    cells = 81
    T = 15
    w = [-1] * cells
    # Build membership
    cell_groups: List[List[int]] = [[] for _ in range(cells)]
    for gi, g in enumerate(groups):
        for i in g:
            cell_groups[i].append(gi)
    # Order by MRV (domain width), then index for stability
    order = sorted(range(cells), key=lambda i: (domain[i][1] - domain[i][0], i))
    # Group running bounds
    current_sum = [0] * len(groups)
    current_min_remaining = [sum(domain[i][0] for i in g) for g in groups]
    current_max_remaining = [sum(domain[i][1] for i in g) for g in groups]

    def dfs(idx: int = 0) -> bool:
        if idx == len(order):
            return True
        i = order[idx]
        lo, hi = domain[i]
        for val in range(lo, hi + 1):
            saved = []
            ok = True
            for gi in cell_groups[i]:
                saved.append((gi, current_sum[gi], current_min_remaining[gi], current_max_remaining[gi]))
                current_sum[gi] += val
                current_min_remaining[gi] -= domain[i][0]
                current_max_remaining[gi] -= domain[i][1]
                if current_sum[gi] + current_min_remaining[gi] > T or current_sum[gi] + current_max_remaining[gi] < T:
                    ok = False
                    break
            if ok:
                w[i] = val
                if dfs(idx + 1):
                    return True
                w[i] = -1
            for gi, s, mn, mx in saved:
                current_sum[gi], current_min_remaining[gi], current_max_remaining[gi] = s, mn, mx
        return False

    assert dfs(), "No solution found"
    return w


def build_x_from_w(w: List[int], forced_one: List[int], forced_one_mask: List[int], forced_zero_mask: List[int]) -> int:
    cells = 81
    nibbles = [0] * cells
    for i in range(cells):
        need = w[i] - forced_one[i]
        val = forced_one_mask[i]
        for b in range(4):
            if need == 0:
                break
            bitpos = 4 * i + b
            # Only set free bits (where A has 0)
            if ((A >> bitpos) & 1) == 0:
                val |= (1 << b)
                need -= 1
        assert need == 0, f"Cannot satisfy cell {i}"
        assert (val & forced_zero_mask[i]) == 0
        assert (val & 0xF).bit_count() == w[i]
        nibbles[i] = val & 0xF
    x = 0
    for i in range(cells):
        x |= (nibbles[i] << (4 * i))
    return x


def validate_x(x: int) -> None:
    # Validate both sets of constraints
    trans = str.maketrans('1b', 'fx')
    for y in YS:
        M = int(bin(y).translate(trans), 0)
        assert (M & x).bit_count() == 15
    assert (x & A) == B


def solve_hex() -> Tuple[str, List[int]]:
    groups = build_groups(YS)
    domain, forced_one, forced_one_mask, forced_zero_mask = derive_domains(A, B)
    w = solve_popcounts(groups, domain)
    x = build_x_from_w(w, forced_one, forced_one_mask, forced_zero_mask)
    return format(x, 'x'), w


def submit_remote(hex_str: str, host: str = 'square-cipher.challs.pwnoh.io', port: int = 1337) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            _ = ssock.recv(4096)
            ssock.sendall((hex_str + '\n').encode())
            data = ssock.recv(4096)
            return data.decode(errors='ignore').strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--verify', action='store_true', help='Validate locally before printing hex')
    ap.add_argument('--grid', action='store_true', help='Print 9x9 grid of nibble popcounts')
    ap.add_argument('--submit', action='store_true', help='Send to remote and print response')
    args = ap.parse_args()

    hex_str, w = solve_hex()
    if args.verify:
        validate_x(int(hex_str, 16))
    if args.grid:
        for r in range(9):
            print(' '.join(str(w[9 * r + c]) for c in range(9)))
    print(hex_str)
    if args.submit:
        try:
            resp = submit_remote(hex_str)
            print(resp)
        except Exception as e:
            print(f"[!] Submit failed: {e}")


if __name__ == '__main__':
    main()

