from befunge_runner import load_program_from_binary

prog = load_program_from_binary('befuddled', 0x8038, 0x52, 25)
PRINT_U_SPOTS = {(2, 4), (5, 4), (26, 1)}


def event_seq(mid: bytes, max_steps: int = 1000000):
    pre = b'bctf{'
    s = pre + mid + b'}\n'
    grid = [row[:] for row in prog]
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


if __name__ == '__main__':
    suf = b'A_unC0mp1labl3'
    pool = bytes(range(32, 127))
    # Try finding any pair that changes the last gate's pos or zeroes it
    pos_target = (51, 3)
    for X in pool:
        for Y in pool:
            seq = event_seq(bytes([X, Y]) + suf)
            op, pos, val = seq[-1]
            if pos != pos_target or val == 0:
                print('Found pair', chr(X), chr(Y), '-> last', (op, pos, val), 'len', len(seq))
                raise SystemExit(0)
    print('No pair changed last gate or zeroed it.')

