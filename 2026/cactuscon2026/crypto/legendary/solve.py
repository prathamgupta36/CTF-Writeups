#!/usr/bin/env python3
import ast
import re
import socket
import sys

E = 65537


def legendre_symbol(a, p):
    a %= p
    if a == 0:
        return 0
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def bits_to_bytes(bits):
    out = bytearray()
    usable = len(bits) - (len(bits) % 8)
    for i in range(0, usable, 8):
        out.append(int(bits[i:i + 8], 2))
    return bytes(out)


def score_plaintext(data):
    score = 0
    if b"flag{" in data:
        score += 1000
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    score += printable
    return score


def decode_by_mapping(ciphers, one_value):
    bits = ''.join('1' if c == one_value else '0' for c in ciphers)
    return bits_to_bytes(bits)


def parse_input(text):
    p = None
    b = None
    m = re.search(r"\bp\s*=\s*(\d+)", text)
    if m:
        p = int(m.group(1))
    m = re.search(r"\bb\s*=\s*(\d+)", text)
    if m:
        b = int(m.group(1))

    m = re.search(r"\[[^\]]+\]", text, re.S)
    if not m:
        return p, b, None
    ciphers = ast.literal_eval(m.group(0))
    return p, b, ciphers


def solve_from_ciphers(ciphers, p=None, b=None):
    values = sorted(set(ciphers))
    value_set = set(values)
    if len(values) < 2:
        raise ValueError("not enough distinct ciphertext values")

    if p is None and len(values) == 2:
        p = values[0] + values[1]

    candidates = []
    if p is not None and legendre_symbol(-1, p) == -1:
        bits = ''.join('1' if legendre_symbol(c, p) == 1 else '0' for c in ciphers)
        candidates.append(bits_to_bytes(bits))

    if p is not None and b is not None:
        n = pow(b, E, p)
        if n in value_set or (-n) % p in value_set:
            candidates.append(decode_by_mapping(ciphers, n))

    if len(values) == 2:
        candidates.append(decode_by_mapping(ciphers, values[0]))
        candidates.append(decode_by_mapping(ciphers, values[1]))

    if candidates:
        return max(candidates, key=score_plaintext)

    raise ValueError("unexpected ciphertext format")


def solve_from_text(text):
    p, b, ciphers = parse_input(text)
    if ciphers is None:
        raise ValueError("cipher list not found")
    return solve_from_ciphers(ciphers, p=p, b=b)


def solve_from_socket(host, port):
    with socket.create_connection((host, port)) as sock:
        sock.settimeout(2.0)
        data = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            try:
                _p, _b, _c = parse_input(data.decode(errors="ignore"))
            except Exception:
                _c = None
            if _c is not None:
                break

        text = data.decode(errors="ignore")
        flag = solve_from_text(text)
        sock.sendall(flag + b"\n")

        try:
            more = sock.recv(4096)
            if more:
                sys.stdout.write(text)
                sys.stdout.write(more.decode(errors="ignore"))
            else:
                sys.stdout.write(text)
        except socket.timeout:
            sys.stdout.write(text)


if __name__ == "__main__":
    if len(sys.argv) == 3:
        solve_from_socket(sys.argv[1], int(sys.argv[2]))
        sys.exit(0)

    input_text = sys.stdin.read()
    if not input_text.strip():
        print("Usage: solve.py <host> <port>  or pipe challenge text via stdin")
        sys.exit(1)

    flag = solve_from_text(input_text)
    sys.stdout.write(flag.decode(errors="ignore"))
    sys.stdout.write("\n")
