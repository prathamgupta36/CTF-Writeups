#!/usr/bin/env python3
import math
import re
import socket
import subprocess
from typing import Iterable

from fpylll import IntegerMatrix, LLL
import sympy as sp

HOST = "chall.lac.tf"
PORT = 31181
E = 65537
L = 67
A = 10**L
R = (10**L - 1) // 9
K = (6 * R) * (10 ** (2 * L)) + (6 * R) * (10**L) + (7 * R)


def fetch_challenge() -> tuple[int, int]:
    s = socket.create_connection((HOST, PORT))
    buf = b""
    while b"solution:" not in buf:
        data = s.recv(4096)
        if not data:
            break
        buf += data
    text = buf.decode()
    m = re.search(r"sh -s (\S+)", text)
    if not m:
        raise RuntimeError("pow challenge not found")
    challenge = m.group(1)
    cmd = f"curl -sSfL https://pwn.red/pow | sh -s {challenge}"
    solution = subprocess.check_output(cmd, shell=True).decode().strip()
    s.sendall((solution + "\n").encode())
    data = s.recv(4096).decode()
    s.close()
    m = re.search(r"n=(\d+)\s+c=(\d+)", data)
    if not m:
        raise RuntimeError("n/c not found")
    return int(m.group(1)), int(m.group(2))


def coppersmith_howgrave_univariate(
    pol_coeffs: list[int], modulus: int, beta: float, mm: int, tt: int, xx: int
) -> Iterable[int]:
    dd = len(pol_coeffs) - 1
    nn = dd * mm + tt
    if pol_coeffs[-1] != 1:
        raise ValueError("polynomial must be monic")

    pol_scaled = [pol_coeffs[i] * (xx**i) for i in range(len(pol_coeffs))]

    def poly_mul(a: list[int], b: list[int]) -> list[int]:
        res = [0] * (len(a) + len(b) - 1)
        for i, ai in enumerate(a):
            for j, bj in enumerate(b):
                res[i + j] += ai * bj
        return res

    def poly_pow(base: list[int], exp: int) -> list[int]:
        res = [1]
        for _ in range(exp):
            res = poly_mul(res, base)
        return res

    gg: list[list[int]] = []
    for ii in range(mm):
        pol_pow = poly_pow(pol_scaled, ii)
        for jj in range(dd):
            factor = (modulus ** (mm - ii)) * (xx**jj)
            coeffs = [c * factor for c in pol_pow]
            coeffs = [0] * jj + coeffs
            gg.append(coeffs)
    pol_pow_m = poly_pow(pol_scaled, mm)
    for ii in range(tt):
        factor = xx**ii
        coeffs = [c * factor for c in pol_pow_m]
        coeffs = [0] * ii + coeffs
        gg.append(coeffs)

    basis = IntegerMatrix(nn, nn)
    for i in range(nn):
        coeffs = gg[i]
        for j in range(min(len(coeffs), i + 1)):
            basis[i, j] = coeffs[j]

    LLL.reduction(basis)

    roots = set()
    x = sp.symbols("x")
    for row in range(nn):
        vec = [int(basis[row, i]) for i in range(nn)]
        new_coeffs = []
        ok = True
        for i, c in enumerate(vec):
            denom = xx**i
            if c % denom != 0:
                ok = False
                break
            new_coeffs.append(c // denom)
        if not ok:
            continue
        while new_coeffs and new_coeffs[-1] == 0:
            new_coeffs.pop()
        if not new_coeffs:
            continue
        poly = sum(sp.Integer(new_coeffs[i]) * x**i for i in range(len(new_coeffs)))
        for r, _mult in sp.roots(poly).items():
            if r.is_integer:
                roots.add(int(r))
    return roots


def main() -> None:
    n, c = fetch_challenge()
    a_inv = pow(A, -1, n)
    b = (K * a_inv) % n

    beta = 0.5
    epsilon = beta / 7
    mm = math.ceil(beta**2 / (1 * epsilon))
    tt = math.floor(1 * mm * ((1 / beta) - 1))
    xx = A

    roots = coppersmith_howgrave_univariate([b, 1], n, beta, mm, tt, xx)
    for r in roots:
        if r < 0 or r >= A:
            continue
        p = math.gcd(A * r + K, n)
        if p != 1 and p != n:
            q = n // p
            phi = (p - 1) * (q - 1)
            d = pow(E, -1, phi)
            m = pow(c, d, n)
            msg = m.to_bytes((m.bit_length() + 7) // 8, "big")
            print(msg.decode())
            return
    raise RuntimeError("root not found")


if __name__ == "__main__":
    main()
