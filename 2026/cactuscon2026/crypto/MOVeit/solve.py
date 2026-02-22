#!/usr/bin/env python3
import argparse
import math
import re
import socket
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sympy.ntheory.modular import crt


P = 14537114296651069957
A = -30
B = 56
N = P + 1
FACTORS = [2, 172981, 42019396051159]


def ec_add(Pt, Qt):
    if Pt is None:
        return Qt
    if Qt is None:
        return Pt
    x1, y1 = Pt
    x2, y2 = Qt
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if Pt != Qt:
        den = (x2 - x1) % P
        m = (y2 - y1) * pow(den, -1, P) % P
    else:
        if y1 == 0:
            return None
        den = (2 * y1) % P
        m = (3 * x1 * x1 + A) * pow(den, -1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def ec_mul(k, Pt):
    res = None
    add = Pt
    while k > 0:
        if k & 1:
            res = ec_add(res, add)
        add = ec_add(add, add)
        k >>= 1
    return res


def point_key(Pt):
    if Pt is None:
        return None
    x, y = Pt
    return (x << 1) | (y & 1)


def bsgs_ecdlp(G, H, q):
    m = math.isqrt(q) + 1

    table = {}
    R = None
    for j in range(m):
        table[point_key(R)] = j
        R = ec_add(R, G)

    mG = ec_mul(m, G)
    neg_mG = (mG[0], (-mG[1]) % P) if mG is not None else None

    T = H
    for i in range(m + 1):
        key = point_key(T)
        if key in table:
            return (i * m + table[key]) % q
        T = ec_add(T, neg_mG)
    raise ValueError("log not found")


def solve_dlp(G, H):
    mods = []
    rems = []
    for q in FACTORS:
        Gq = ec_mul(N // q, G)
        Hq = ec_mul(N // q, H)
        if q <= 200000:
            cur = None
            found = None
            for d in range(q):
                if cur == Hq:
                    found = d
                    break
                cur = ec_add(cur, Gq)
            if found is None:
                raise ValueError("small DLP failed")
            d = found
        else:
            d = bsgs_ecdlp(Gq, Hq, q)
        mods.append(q)
        rems.append(d)
    x, _ = crt(mods, rems)
    return int(x % N)


def parse_output(text):
    def parse_point(label):
        rgx = rf"{label}:\\s*\\((\\d+)\\s*:\\s*(\\d+)\\s*:\\s*1\\)"
        m = re.search(rgx, text)
        if not m:
            raise ValueError(f"missing {label}")
        return (int(m.group(1)), int(m.group(2)))

    G = parse_point("Generator")
    P1 = parse_point("Alice Public key")
    P2 = parse_point("Bob Public key")
    m = re.search(r"Encrypted flag:\\s*([0-9a-fA-F]+)", text)
    if not m:
        raise ValueError("missing ciphertext")
    ct_hex = m.group(1).lower()
    return G, P1, P2, ct_hex


def fetch_from_remote(host, port):
    data = b""
    with socket.create_connection((host, port)) as s:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode(errors="ignore")


def main():
    parser = argparse.ArgumentParser(description="Solve MOVeit :: 001")
    parser.add_argument("--host", default="159.65.255.102")
    parser.add_argument("--port", type=int, default=31968)
    parser.add_argument("--file", help="Read server output from file instead of TCP")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        text = fetch_from_remote(args.host, args.port)

    G, P1, P2, ct_hex = parse_output(text)
    n_a = solve_dlp(G, P1)
    S = ec_mul(n_a, P2)
    Sx = S[0]
    key = str(Sx).encode()[:16]
    ct = bytes.fromhex(ct_hex)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except ValueError:
        pass
    print(pt.decode(errors="replace"))


if __name__ == "__main__":
    main()
