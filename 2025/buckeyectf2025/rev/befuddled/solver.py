from befunge_runner import load_program_from_binary, run_befunge, load_program
import json
import os

DEFAULT_BIN = 'befuddled'
DEFAULT_OFF = 0x8038
DEFAULT_W = 0x52
DEFAULT_H = 25

prog = load_program_from_binary(DEFAULT_BIN, DEFAULT_OFF, DEFAULT_W, DEFAULT_H)
PRINT_U_SPOTS = {(2, 4), (5, 4), (26, 1)}


def resolve_grid(program_file: str | None = None,
                 binary_path: str | None = None,
                 file_off: int | None = None,
                 width: int | None = None,
                 height: int | None = None):
    if program_file:
        return load_program(program_file)
    if binary_path or file_off or width or height:
        bp = binary_path or DEFAULT_BIN
        off = file_off if file_off is not None else DEFAULT_OFF
        w = width if width is not None else DEFAULT_W
        h = height if height is not None else DEFAULT_H
        return load_program_from_binary(bp, off, w, h)
    return [row[:] for row in prog]


def event_seq(mid: bytes, max_steps: int = 600000, grid_in: list[list[int]] | None = None):
    pre = b'bctf{'
    s = pre + mid + b'}\n'
    grid = [row[:] for row in (grid_in if grid_in is not None else prog)]
    H, W = len(grid), len(grid[0])
    x = y = 0
    dx, dy = 1, 0
    stack = []
    string_mode = False
    inp = list(s)
    seq = []
    for _ in range(max_steps):
        instr = grid[y][x]
        if instr == 0xFF:
            instr = 32
        ch = chr(instr)
        if string_mode:
            if ch == '"':
                string_mode = False
            else:
                stack.append(instr)
        else:
            if ch == ' ':
                pass
            elif '0' <= ch <= '9':
                stack.append(ord(ch) - 48)
            elif ch == '+':
                b = stack.pop() if stack else 0
                a = stack.pop() if stack else 0
                stack.append(a + b)
            elif ch == '-':
                b = stack.pop() if stack else 0
                a = stack.pop() if stack else 0
                stack.append(a - b)
            elif ch == '*':
                b = stack.pop() if stack else 0
                a = stack.pop() if stack else 0
                stack.append(a * b)
            elif ch == '/':
                b = stack.pop() if stack else 0
                a = stack.pop() if stack else 0
                stack.append(0 if b == 0 else a // b)
            elif ch == '%':
                b = stack.pop() if stack else 0
                a = stack.pop() if stack else 0
                stack.append(0 if b == 0 else a % b)
            elif ch == '!':
                a = stack.pop() if stack else 0
                stack.append(0 if a else 1)
            elif ch == '`':
                b = stack.pop() if stack else 0
                a = stack.pop() if stack else 0
                stack.append(1 if a > b else 0)
            elif ch == '>':
                dx, dy = 1, 0
            elif ch == '<':
                dx, dy = -1, 0
            elif ch == '^':
                dx, dy = 0, -1
            elif ch == 'v':
                dx, dy = 0, 1
            elif ch == '?':
                dx, dy = 1, 0
            elif ch == '_':
                a = stack.pop() if stack else 0
                if (x, y) not in PRINT_U_SPOTS:
                    seq.append(('_', (x, y), a))
                dx, dy = (1, 0) if a == 0 else (-1, 0)
            elif ch == '|':
                a = stack.pop() if stack else 0
                seq.append(('|', (x, y), a))
                dx, dy = (0, 1) if a == 0 else (0, -1)
            elif ch == '"':
                string_mode = True
            elif ch == ':':
                a = stack.pop() if stack else 0
                stack.append(a)
                stack.append(a)
            elif ch == '\\':
                a = stack.pop() if stack else 0
                b = stack.pop() if stack else 0
                stack.append(a)
                stack.append(b)
            elif ch == '$':
                _ = stack.pop() if stack else 0
            elif ch == '.':
                a = stack.pop() if stack else 0
            elif ch == ',':
                a = stack.pop() if stack else 0
            elif ch == '#':
                x = (x + dx) % W
                y = (y + dy) % H
            elif ch == 'p':
                y_ = stack.pop() if stack else 0
                x_ = stack.pop() if stack else 0
                v = stack.pop() if stack else 0
                grid[y_ % H][x_ % W] = v & 0xFF
            elif ch == 'g':
                y_ = stack.pop() if stack else 0
                x_ = stack.pop() if stack else 0
                stack.append(grid[y_ % H][x_ % W])
            elif ch == '&':
                stack.append(0)
            elif ch == '~':
                stack.append(inp.pop(0) if inp else 0)
            elif ch == '@':
                break
        x = (x + dx) % W
        y = (y + dy) % H
    return seq


def first_diff(a, b):
    L = min(len(a), len(b))
    for i in range(L):
        if a[i] != b[i]:
            return i
    return L


def solve_depth_limited(max_depth=24, start_suffix: bytes | None = None, grid_in: list[list[int]] | None = None):
    # DFS over choosing target gate values {0,1} at each step; derive char using linear map
    def first_diff_idx(sa, sb):
        L = min(len(sa), len(sb))
        for i in range(L):
            if sa[i] != sb[i]:
                return i
        return L

    def candidate_chars_for_gate(suffix: bytes):
        # Find earliest differing gate index for 'A' vs 'B'
        sa = event_seq(bytes([65]) + suffix, grid_in=grid_in)
        sb = event_seq(bytes([66]) + suffix, grid_in=grid_in)
        i = first_diff_idx(sa, sb)
        if i >= len(sa) or i >= len(sb):
            return [], i
        op, pos, va = sa[i]
        _, pos_b, vb = sb[i]
        if pos != pos_b or op not in ('|', '_'):
            return [], i
        # Slope check
        if (vb - va) == 1:
            K = 65 - va
            cands = []
            for t in (0, 1):
                c = K + t
                if 32 <= c <= 126:
                    cands.append(c)
            return cands, i
        # Nonlinear: brute over printable ASCII and pick chars that set this gate to 0 or 1
        cands = []
        for c in range(32, 127):
            sc = event_seq(bytes([c]) + suffix, grid_in=grid_in)
            if i < len(sc) and sc[i][0] == op and sc[i][1] == pos and sc[i][2] in (0, 1):
                cands.append(c)
        # If still empty, broaden to any char that changes the value (to escape constants)
        if not cands:
            seen = set()
            for c in range(32, 127):
                sc = event_seq(bytes([c]) + suffix, grid_in=grid_in)
                if i < len(sc) and sc[i][0] == op and sc[i][1] == pos:
                    val = sc[i][2]
                    if val not in seen:
                        cands.append(c)
                        seen.add(val)
                        if len(cands) >= 4:
                            break
        return cands, i

    def dfs(suffix: bytes, depth: int):
        if depth >= max_depth:
            flag = b'bctf{' + suffix + b'}\n'
            out, status, *_ = run_befunge([row[:] for row in (grid_in if grid_in is not None else prog)], flag)
            if b'Correct!!!' in out:
                print(flag.decode('latin1').strip())
                raise SystemExit
            return
        cands, i = candidate_chars_for_gate(suffix)
        if not cands:
            # No further influence; test flag
            flag = b'bctf{' + suffix + b'}\n'
            out, status, *_ = run_befunge([row[:] for row in (grid_in if grid_in is not None else prog)], flag)
            if b'Correct!!!' in out:
                print(flag.decode('latin1').strip())
                raise SystemExit
            return
        # try candidates in a reasonable order
        for c in cands:
            dfs(bytes([c]) + suffix, depth + 1)

    try:
        if start_suffix is None:
            start_suffix = b'3'
        dfs(start_suffix, 0)
    except SystemExit:
        return
    print('No solution found up to depth', max_depth)


def _alphabet_from_name(name: str) -> list[int]:
    name = name.lower()
    if name in ('printable', 'ascii'):
        return list(range(32, 127))
    if name == 'alnum':
        return list(range(48,58)) + list(range(65,91)) + list(range(97,123))
    if name == 'alpha':
        return list(range(65,91)) + list(range(97,123))
    if name == 'lower':
        return list(range(97,123))
    if name == 'upper':
        return list(range(65,91))
    if name == 'hex':
        return [ord(ch) for ch in '0123456789abcdef']
    if name == 'word':  # letters+digits+underscore
        return list(range(48,58)) + list(range(65,91)) + list(range(97,123)) + [95]
    return list(range(32, 127))


def greedy_solve(max_steps: int = 64, start_suffix: bytes = b'', verbose: bool = False,
                 alphabet: list[int] | None = None,
                 save_path: str | None = None,
                 save_every: int = 1,
                 grid_in: list[list[int]] | None = None) -> bytes:
    """Greedy reconstruction from the right: at each step, choose the printable
    ASCII char that maximizes the number of gate events before halting.

    Returns the recovered suffix (inside braces, right-to-left assembled).
    """
    PRINTABLE = alphabet if alphabet is not None else list(range(32, 127))

    def pref_score(ch: int) -> int:
        # Prefer alnum and underscore to break ties deterministically
        if 48 <= ch <= 57 or 65 <= ch <= 90 or 97 <= ch <= 122 or ch == 95:
            return 2
        return 1

    S = start_suffix
    for step in range(max_steps):
        best_len = -1
        best_cs: list[int] = []
        for c in PRINTABLE:
            L = len(event_seq(bytes([c]) + S, grid_in=grid_in))
            if L > best_len:
                best_len = L
                best_cs = [c]
            elif L == best_len:
                best_cs.append(c)
        # deterministic pick among ties
        best_cs.sort(key=lambda ch: (-pref_score(ch), ch))
        c = best_cs[0]
        S = bytes([c]) + S
        if verbose:
            print(f"[greedy] step {step:02d} chose '{chr(c)}' -> seq_len={best_len}")
        if save_path and (step % max(1, save_every) == 0):
            try:
                with open(save_path, 'w', encoding='utf-8') as f:
                    json.dump({
                        'suffix': S.decode('latin1'),
                        'step': step,
                        'last_char': chr(c),
                        'seq_len': best_len,
                    }, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
        # quick acceptance test each step
        flag = b'bctf{' + S + b'}\n'
        out, *_ = run_befunge([row[:] for row in (grid_in if grid_in is not None else prog)], flag)
        if b'Correct!!!' in out:
            if verbose:
                print('[greedy] Accepted by VM')
            break
    return S


def beam_solve(depth: int = 60,
               beam: int = 2000,
               branch: int = 8,
               alphabet: list[int] | None = None,
               grid_in: list[list[int]] | None = None,
               verbose: bool = False) -> bytes | None:
    ALPH = alphabet if alphabet is not None else list(range(32,127))

    def first_diff(sa, sb):
        L = min(len(sa), len(sb))
        for i in range(L):
            if sa[i] != sb[i]:
                return i
        return None

    def candidates_for_suffix(suffix: bytes):
        sa = event_seq(bytes([65]) + suffix, grid_in=grid_in)
        sb = event_seq(bytes([66]) + suffix, grid_in=grid_in)
        i = first_diff(sa, sb)
        if i is None:
            return [], None
        op, pos, va = sa[i]
        _, pos_b, vb = sb[i]
        if pos != pos_b or op not in ('|', '_'):
            return [], i
        cands = set()
        if (vb - va) == 1:
            K = 65 - va
            for t in (0, 1):
                c = K + t
                if 32 <= c <= 126:
                    cands.add(c)
        else:
            for c in ALPH:
                sc = event_seq(bytes([c]) + suffix, grid_in=grid_in)
                if i < len(sc) and sc[i][0] == op and sc[i][1] == pos and sc[i][2] in (0, 1):
                    cands.add(c)
        ranked = []
        for c in cands:
            ns = bytes([c]) + suffix
            seq = event_seq(ns, grid_in=grid_in)
            sa2 = event_seq(bytes([65]) + ns, grid_in=grid_in)
            sb2 = event_seq(bytes([66]) + ns, grid_in=grid_in)
            idx2 = first_diff(sa2, sb2) is not None
            ranked.append((-(len(seq)), idx2, c))
        ranked.sort()
        return [c for *_x, c in ranked], i

    frontier = [(len(event_seq(b'', grid_in=grid_in)), b'')]
    seen = {b''}
    for d in range(depth):
        new = []
        for _, suf in frontier:
            cands, _ = candidates_for_suffix(suf)
            if not cands:
                flag = b'bctf{' + suf + b'}\n'
                out, *_ = run_befunge([row[:] for row in (grid_in if grid_in is not None else prog)], flag)
                if b'Correct!!!' in out:
                    return suf
                continue
            for c in cands[:branch]:
                ns = bytes([c]) + suf
                if ns in seen:
                    continue
                seen.add(ns)
                new.append((len(event_seq(ns, grid_in=grid_in)), ns))
        if not new:
            break
        new.sort(reverse=True)
        frontier = new[:beam]
        if verbose and frontier:
            print(f"[beam] depth {d} frontier_size={len(frontier)} best_len={frontier[0][0]}")
    for _, suf in frontier:
        flag = b'bctf{' + suf + b'}\n'
        out, *_ = run_befunge([row[:] for row in (grid_in if grid_in is not None else prog)], flag)
        if b'Correct!!!' in out:
            return suf
    return None


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['greedy', 'dfs', 'beam', 'verify', 'events'], default='greedy', help='Mode to run')
    ap.add_argument('--max-steps', type=int, default=64, help='Max steps/depth for greedy/dfs')
    ap.add_argument('--start', type=str, default='', help='Starting suffix (inside braces)')
    ap.add_argument('--alphabet', type=str, default='printable', help='Alphabet name (printable, alnum, alpha, lower, upper, hex, word) or literal characters')
    ap.add_argument('--save', type=str, default='', help='Save progress JSON path (greedy mode)')
    ap.add_argument('--save-every', type=int, default=1, help='Save every N steps (greedy mode)')
    ap.add_argument('--beam', type=int, default=2000, help='Beam width (beam mode)')
    ap.add_argument('--branch', type=int, default=8, help='Candidates expanded per node (beam mode)')
    ap.add_argument('--depth', type=int, default=60, help='Depth (beam mode)')
    ap.add_argument('--candidate', type=str, default='', help='Candidate inside braces for verify/events')
    ap.add_argument('--events-limit', type=int, default=20, help='Events to show (events mode)')
    ap.add_argument('--program-file', type=str, default='', help='Path to program.bf to load instead of binary')
    ap.add_argument('--binary', type=str, default=DEFAULT_BIN, help='Binary path (when loading from binary)')
    ap.add_argument('--offset', type=lambda x: int(x, 0), default=DEFAULT_OFF, help='File offset (hex or dec) for binary grid')
    ap.add_argument('--width', type=int, default=DEFAULT_W, help='Grid width for binary')
    ap.add_argument('--height', type=int, default=DEFAULT_H, help='Grid height for binary')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    # Resolve grid according to CLI
    grid_cli = None
    if args.program_file:
        grid_cli = resolve_grid(program_file=args.program_file)
    elif args.binary or args.offset or args.width or args.height:
        grid_cli = resolve_grid(binary_path=args.binary, file_off=args.offset, width=args.width, height=args.height)

    # Alphabet processing
    if len(args.alphabet) == 1 or args.alphabet in ('printable', 'alnum', 'alpha', 'lower', 'upper', 'hex', 'word', 'ascii'):
        alphabet = _alphabet_from_name(args.alphabet)
    else:
        alphabet = [ord(ch) for ch in args.alphabet]

    if args.mode == 'greedy':
        suffix = greedy_solve(args.max_steps,
                              args.start.encode('latin1'),
                              verbose=args.verbose,
                              alphabet=alphabet,
                              save_path=(args.save or None),
                              save_every=args.save_every,
                              grid_in=grid_cli)
        candidate = b'bctf{' + suffix + b'}\n'
        out, *_ = run_befunge([row[:] for row in (grid_cli if grid_cli is not None else prog)], candidate)
        print((b'bctf{' + suffix + b'}').decode('latin1'))
        if b'Correct!!!' not in out and args.verbose:
            print('Note: candidate not accepted yet; try increasing --max-steps or different start.', flush=True)
    elif args.mode == 'dfs':
        solve_depth_limited(args.max_steps, start_suffix=args.start.encode('latin1') if args.start else None, grid_in=grid_cli)
    elif args.mode == 'beam':
        suf = beam_solve(args.depth, args.beam, args.branch, alphabet=alphabet, grid_in=grid_cli, verbose=args.verbose)
        if suf is not None:
            print((b'bctf{' + suf + b'}').decode('latin1'))
        else:
            print('No solution in beam search.')
    elif args.mode == 'verify':
        cand = args.candidate
        if cand.startswith('bctf{') and cand.endswith('}'):
            data = cand.encode('latin1') + b'\n'
        else:
            data = (b'bctf{' + cand.encode('latin1') + b'}\n')
        out, *_ = run_befunge([row[:] for row in (grid_cli if grid_cli is not None else prog)], data)
        print(out.decode('latin1'), end='')
    elif args.mode == 'events':
        cand = args.candidate.encode('latin1')
        seq = event_seq(cand, grid_in=grid_cli)
        print('events:', len(seq))
        for i, e in enumerate(seq[:max(0, args.events_limit)]):
            print(i, e)
