#!/usr/bin/env python3
import re
import socket
import sys

HOST = "challenges3.ctf.sd"
PORT = 33196

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
G = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


def inv(a):
    return pow(a, -1, P)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * inv(2 * y1 % P) % P
    else:
        lam = (y2 - y1) * inv((x2 - x1) % P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, pt):
    res = None
    base = pt
    while k > 0:
        if k & 1:
            res = point_add(res, base)
        base = point_add(base, base)
        k >>= 1
    return res


def point_neg(pt):
    if pt is None:
        return None
    x, y = pt
    return (x, (-y) % P)


def fmt_point(pt):
    return f"Point({pt[0]}, {pt[1]})\n".encode()


class Conn:
    def __init__(self, s):
        self.s = s
        self.buf = b""

    def _recv_more(self):
        data = self.s.recv(4096)
        if not data:
            raise EOFError("connection closed")
        self.buf += data

    def recv_until(self, token: bytes):
        while token not in self.buf:
            self._recv_more()
        idx = self.buf.index(token) + len(token)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def recv_point_after(self, label: bytes):
        pat = re.compile(re.escape(label) + rb"Point\((\d+),\s*(\d+)\)")
        while True:
            m = pat.search(self.buf)
            if m:
                x = int(m.group(1))
                y = int(m.group(2))
                self.buf = self.buf[m.end():]
                return (x, y)
            self._recv_more()


def main():
    host = HOST
    port = PORT
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    s = socket.create_connection((host, port))
    conn = Conn(s)

    # Phase 1, Query 1: send a point on the singular curve y^2 = x^3 (B = 0).
    conn.recv_until(b"Input C1 > ")
    t = 2
    x = (t * t) % P
    y = (t * t * t) % P
    P_sing = (x, y)
    conn.s.sendall(fmt_point(P_sing))
    conn.recv_until(b"Input C2 > ")
    conn.s.sendall(fmt_point(P_sing))

    S = conn.recv_point_after(b"Output S > ")
    # For y^2 = x^3, the group law reduces to addition on u = x / y.
    u = x * inv(y) % P
    u_s = S[0] * inv(S[1]) % P
    # S = (1 - d) * P  =>  u_s = (1 - d) * u  =>  d = 1 - u_s / u.
    d = (1 - u_s * inv(u)) % P

    # Burn remaining Phase 1 queries with valid curve points.
    for _ in range(4):
        conn.recv_until(b"Input C1 > ")
        conn.s.sendall(fmt_point(G))
        conn.recv_until(b"Input C2 > ")
        conn.s.sendall(fmt_point(G))
        conn.recv_point_after(b"Output S > ")

    # Phase 2: decrypt points.
    for _ in range(5):
        c1 = conn.recv_point_after(b"Given C1: ")
        c2 = conn.recv_point_after(b"Given C2: ")
        ptext = point_add(c2, point_neg(point_mul(d, c1)))
        conn.recv_until(b"Recovered Point P > ")
        conn.s.sendall(fmt_point(ptext))

    # Print remainder (flag)
    rest = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            rest += chunk
    except Exception:
        pass
    if rest:
        print(rest.decode(errors="replace"))


if __name__ == "__main__":
    main()
