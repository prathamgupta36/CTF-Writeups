#!/usr/bin/env python3
from __future__ import annotations
import sys
import random


def load_program(path: str) -> list[list[int]]:
    with open(path, 'r', encoding='latin1') as f:
        lines = f.read().splitlines()
    # Normalize to 25x80 grid (pad with spaces)
    H = 25
    W = 80
    grid = [[ord(' ') for _ in range(W)] for _ in range(H)]
    for r in range(min(H, len(lines))):
        line = lines[r]
        for c in range(min(W, len(line))):
            grid[r][c] = ord(line[c])
    return grid


def load_program_from_binary(bin_path: str, file_off: int, width: int, height: int) -> list[list[int]]:
    with open(bin_path, 'rb') as f:
        f.seek(file_off)
        raw = f.read(width * height)
    grid = []
    for r in range(height):
        row = list(raw[r*width:(r+1)*width])
        grid.append(row)
    return grid


class RunStatus:
    OK = 'ok'
    NEED_INPUT = 'need_input'
    HALTED = 'halted'


def run_befunge(grid: list[list[int]], input_data: bytes, trace: bool = False, stop_on_need_input: bool = False):
    H, W = len(grid), len(grid[0])
    x, y = 0, 0
    dx, dy = 1, 0  # start moving right
    stack: list[int] = []
    out: bytearray = bytearray()
    ip_steps = 0
    string_mode = False
    inp_i = 0

    def pop() -> int:
        return stack.pop() if stack else 0

    def push(v: int):
        stack.append(v & 0xFFFFFFFFFFFFFFFF)  # keep it bounded but let it be big

    status = RunStatus.OK
    read_char_count = 0
    while True:
        ip_steps += 1
        if ip_steps > 10_000_000:
            raise RuntimeError("Too many steps; possible infinite loop")
        instr = grid[y][x]
        if instr == 0xFF:
            instr = ord(' ')
        ch = chr(instr)
        if trace:
            sys.stderr.write(f"({x:02},{y:02}) '{ch}' stk={stack[-8:]}\n")
        if string_mode:
            if ch == '"':
                string_mode = False
            else:
                push(instr)
        else:
            if '0' <= ch <= '9':
                push(ord(ch) - ord('0'))
            elif ch == '+':
                a, b = pop(), pop()
                push(b + a)
            elif ch == '-':
                a, b = pop(), pop()
                push(b - a)
            elif ch == '*':
                a, b = pop(), pop()
                push(b * a)
            elif ch == '/':
                a, b = pop(), pop()
                push(0 if a == 0 else int(b / a))
            elif ch == '%':
                a, b = pop(), pop()
                push(0 if a == 0 else (b % a))
            elif ch == '!':
                a = pop()
                push(0 if a else 1)
            elif ch == '`':
                a, b = pop(), pop()
                push(1 if b > a else 0)
            elif ch == '>':
                dx, dy = 1, 0
            elif ch == '<':
                dx, dy = -1, 0
            elif ch == '^':
                dx, dy = 0, -1
            elif ch == 'v':
                dx, dy = 0, 1
            elif ch == '?':
                dx, dy = random.choice([(1,0),(-1,0),(0,1),(0,-1)])
            elif ch == '_':
                a = pop()
                dx, dy = (1,0) if a == 0 else (-1,0)
            elif ch == '|':
                a = pop()
                dx, dy = (0,1) if a == 0 else (0,-1)
            elif ch == '"':
                string_mode = True
            elif ch == ':':
                a = pop()
                push(a)
                push(a)
            elif ch == '\\':
                a, b = pop(), pop()
                push(a)
                push(b)
            elif ch == '$':
                _ = pop()
            elif ch == '.':
                a = pop()
                out.extend(str(int(a)).encode('ascii'))
                out.append(ord(' '))
            elif ch == ',':
                a = pop()
                out.append(int(a) & 0xFF)
            elif ch == '#':
                # bridge: skip next cell
                x = (x + dx) % W
                y = (y + dy) % H
            elif ch == 'p':
                y_, x_, v = pop(), pop(), pop()
                # Wrap indices
                x_ %= W
                y_ %= H
                grid[y_][x_] = v & 0xFF
            elif ch == 'g':
                y_, x_ = pop(), pop()
                x_ %= W
                y_ %= H
                push(grid[y_][x_])
            elif ch == '&':
                # read integer from input until non-digit delim, support signed
                # fallback: if no input left, push 0
                if inp_i >= len(input_data):
                    if stop_on_need_input:
                        status = RunStatus.NEED_INPUT
                        break
                    push(0)
                else:
                    # parse up to whitespace
                    j = inp_i
                    while j < len(input_data) and input_data[j] in b' \t\r\n':
                        j += 1
                    sign = 1
                    if j < len(input_data) and input_data[j:j+1] == b'-':
                        sign = -1
                        j += 1
                    k = j
                    while k < len(input_data) and input_data[k:k+1].isdigit():
                        k += 1
                    if k == j:
                        val = 0
                    else:
                        val = int(input_data[j:k]) * sign
                    inp_i = k
                    push(val)
            elif ch == '~':
                # read char
                if inp_i >= len(input_data):
                    if stop_on_need_input:
                        status = RunStatus.NEED_INPUT
                        break
                    push(0)
                else:
                    push(input_data[inp_i])
                    inp_i += 1
                read_char_count += 1
            elif ch == '@':
                status = RunStatus.HALTED
                break
            elif ch == ' ':
                pass
            else:
                # Unrecognized; noop
                pass

        # step
        x = (x + dx) % W
        y = (y + dy) % H
    return bytes(out), status, inp_i, (x, y), list(stack), read_char_count, grid


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('program', help='Befunge program file (80x25)')
    ap.add_argument('-i', '--input', help='Input string', default='')
    ap.add_argument('--trace', action='store_true')
    args = ap.parse_args()

    grid = load_program(args.program)
    out, status, _, _, _ = run_befunge(grid, args.input.encode('latin1'), trace=args.trace)
    sys.stdout.buffer.write(out)


if __name__ == '__main__':
    main()
