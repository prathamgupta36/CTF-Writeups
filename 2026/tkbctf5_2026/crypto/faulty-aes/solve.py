#!/usr/bin/env python3
import argparse
import re
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "faulty-aes"))

from aes import AES, inv_s_box, r_con, s_box


def bxor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def get_bit_positions() -> tuple[int, int]:
    source = (ROOT / "faulty-aes" / "aes.py").read_text()

    neutral_text = "Encrypts a single block of 16 byte long plaintext."
    neutral_byte = source.index(neutral_text)
    neutral_bit = neutral_byte * 8

    final_key_line = "add_round_key(plain_state, self._key_matrices[-1])"
    line_byte = source.index(final_key_line)
    one_byte = line_byte + final_key_line.index("1")
    k8_bit = one_byte * 8 + 1

    return neutral_bit, k8_bit


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def query(host: str, port: int, bit: int, answer: bytes | None = None) -> tuple[bytes, bytes]:
    with socket.create_connection((host, port), timeout=10) as sock:
        recv_until(sock, b"pos: ")
        sock.sendall(f"{bit}\n".encode())

        data = recv_until(sock, b"hash: ")
        match = re.search(rb"ct: ([0-9a-f]+)", data)
        if match is None:
            raise RuntimeError(f"unexpected server response: {data!r}")

        ciphertext = bytes.fromhex(match.group(1).decode())
        payload = b"00\n" if answer is None else answer.hex().encode() + b"\n"
        sock.sendall(payload)
        tail = sock.recv(4096)
        return ciphertext, tail


def g_inv(word: bytes, round_idx: int) -> bytes:
    tmp = bytearray(word)
    tmp[0] ^= r_con[round_idx]
    tmp = bytearray(inv_s_box[b] for b in tmp)
    return bytes([tmp[3], tmp[0], tmp[1], tmp[2]])


def recover_last_round_key(delta_10_8: bytes) -> bytes:
    d0, d1, d2, d3 = [delta_10_8[i * 4 : (i + 1) * 4] for i in range(4)]

    w40 = d2
    w41 = d3
    w43_xor_w42 = g_inv(d1, 10)
    w43_xor_w41 = g_inv(bxor(d0, d1), 9)
    w43 = bxor(w43_xor_w41, w41)
    w42 = bxor(w43, w43_xor_w42)

    return w40 + w41 + w42 + w43


def invert_key_schedule(last_round_key: bytes) -> bytes:
    words: list[bytes | None] = [None] * 44
    for i in range(4):
        words[40 + i] = last_round_key[i * 4 : (i + 1) * 4]

    for i in range(43, 3, -1):
        if i % 4 == 0:
            temp = bytearray(words[i - 1][1:] + words[i - 1][:1])
            temp = bytearray(s_box[b] for b in temp)
            temp[0] ^= r_con[i // 4]
            words[i - 4] = bxor(words[i], temp)
        else:
            words[i - 4] = bxor(words[i], words[i - 1])

    return b"".join(words[:4])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="35.194.108.145")
    parser.add_argument("--port", type=int, default=54140)
    args = parser.parse_args()

    neutral_bit, k8_bit = get_bit_positions()

    base_ct, _ = query(args.host, args.port, neutral_bit)
    k8_ct, _ = query(args.host, args.port, k8_bit)

    last_round_key = recover_last_round_key(bxor(base_ct, k8_ct))
    master_key = invert_key_schedule(last_round_key)
    message = AES(master_key).decrypt_block(base_ct)
    hash_value = master_key + message

    _, tail = query(args.host, args.port, neutral_bit, hash_value)

    print(f"neutral_bit={neutral_bit}")
    print(f"k8_bit={k8_bit}")
    print(f"sha256(flag)={hash_value.hex()}")
    print(tail.decode(errors='replace').strip())


if __name__ == "__main__":
    main()
