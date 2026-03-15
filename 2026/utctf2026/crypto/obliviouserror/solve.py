#!/usr/bin/env python3
import re
import socket
from typing import Tuple

HOST = "challenge.utctf.live"
PORT = 8379


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError(f"connection closed before receiving {marker!r}")
        data += chunk
    return data


def long_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def fetch_flag() -> Tuple[int, int, bytes]:
    with socket.create_connection((HOST, PORT)) as sock:
        banner = recv_until(sock, b"Please pick a value k.")
        text = banner.decode()

        n = int(re.search(r"N = (\d+)", text).group(1))
        e = int(re.search(r"e = (\d+)", text).group(1))
        x0 = int(re.search(r"x0: (\d+)", text).group(1))
        x1 = int(re.search(r"x1: (\d+)", text).group(1))

        # The broken code sends v = x0 + (k ^ e) mod N.
        # Pick k so that (k ^ e) == (x1 - x0) mod N, forcing v == x1.
        # That makes one sender-side mask equal to 0 and leaks the hidden message.
        k = ((x1 - x0) % n) ^ e
        sock.sendall(f"{k}\n".encode())

        reply = recv_until(sock, b"Message 2:")
        reply += sock.recv(4096)
        m1 = int(re.search(rb"Message 1:\s+(\d+)", reply).group(1))
        m2 = int(re.search(rb"Message 2:\s+(\d+)", reply).group(1))

    for candidate in (m1, m2):
        decoded = long_to_bytes(candidate)
        if b"utflag{" in decoded:
            return m1, m2, decoded

    raise ValueError("flag not found in returned messages")


if __name__ == "__main__":
    _, _, flag = fetch_flag()
    print(flag.decode().strip())
