#!/usr/bin/env python3
"""Lakectf 2025 – Ez Part solver."""
from __future__ import annotations

import hashlib
import json
import random
import string
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Dict, List, Tuple

from Crypto.Util.number import bytes_to_long

BASE_URL = "http://chall.polygl0ts.ch:6027"
ALPHABET = string.ascii_letters + string.digits


def http_get(path: str) -> str:
    req = urllib.request.Request(BASE_URL + path)
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode()


def http_post(path: str, payload: dict) -> Tuple[str, int]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode(), resp.status
    except urllib.error.HTTPError as e:
        return e.read().decode(), e.code


def fetch_masks() -> List[Tuple[int, int]]:
    raw = http_get("/masks")
    data = json.loads(raw)
    masks: List[Tuple[int, int]] = []
    for hex_val, shift in data["masks"]:
        masks.append((int(hex_val, 16), shift))
    return masks


def fetch_admin_error() -> Tuple[int, List[str]]:
    body, _ = http_post("/prove-id", {"username": "admin", "password": "x"})
    message = json.loads(body)["message"]
    lines = message.split("\n")
    assert lines[0].startswith("Wrong b: ")
    b = int(lines[0][len("Wrong b: "):])
    target = ["" for _ in range(message.count("Wrong mask"))]
    for entry in message.split("Wrong mask : ")[1:]:
        idx_str, rest = entry.split(",", 1)
        mask_idx = int(idx_str)
        target_hash = rest.split("\n")[0].strip()
        target[mask_idx] = target_hash
    return b, target


def recover_prime(samples: int = 3) -> int:
    vals = []
    for _ in range(samples):
        username = f"solver_{random.randrange(1 << 30)}"
        password = random.choice(["AA", "AB", "AC", "BA", "BB"])
        http_post("/create-account", {"username": username, "password": password})
        body, _ = http_post("/prove-id", {"username": username, "password": "dummy"})
        message = json.loads(body)["message"]
        b_line = message.split("\n")[0]
        b_val = int(b_line.split(": ")[1])
        vals.append((bytes_to_long(password.encode()), b_val))
    p_candidate = 0
    for x, b_val in vals:
        diff = abs(pow(3, x, 1 << 2048) - b_val)
        p_candidate = diff if p_candidate == 0 else math_gcd(p_candidate, diff)
    return p_candidate


def math_gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def pow2_dlog(base: int, target: int, modulus: int) -> Tuple[int, int]:
    order = modulus - 1
    k = 0
    tmp = order
    while tmp % 2 == 0:
        tmp //= 2
        k += 1
    q = tmp
    g0 = pow(base, q, modulus)
    h0 = pow(target, q, modulus)
    x = 0
    for j in range(k):
        temp = pow(g0, x, modulus)
        inv = pow(temp, -1, modulus)
        h_j = (h0 * inv) % modulus
        d = pow(h_j, 1 << (k - 1 - j), modulus)
        if d == 1:
            bit = 0
        elif d == modulus - 1:
            bit = 1
        else:
            raise ValueError("unexpected value during discrete log recovery")
        x |= bit << j
    return x, k


@dataclass
class MaskData:
    index: int
    positions: List[int]
    target_hash: str


class MaskSolver:
    def __init__(self, mask_bits: List[MaskData], known_bits: Dict[int, int]):
        self.mask_bits = mask_bits
        self.known_bits = known_bits
        self.hash_cache: Dict[int, str] = {}

    @staticmethod
    def sha256_int(value: int) -> str:
        return hashlib.sha256(str(value).encode()).hexdigest()

    def solve_mask(self, mask: MaskData) -> None:
        positions = mask.positions
        known_val = 0
        unknown_positions = []
        for pos in positions:
            bit = self.known_bits.get(pos)
            if bit is None:
                unknown_positions.append(pos)
            elif bit == 1:
                known_val |= 1 << pos
        unknown = len(unknown_positions)
        if unknown == 0:
            assert self.sha256_int(known_val) == mask.target_hash
            return
        bit_values = [1 << pos for pos in unknown_positions]
        current = known_val
        prev_gray = 0
        for combo in range(1 << unknown):
            if combo:
                gray = combo ^ (combo >> 1)
                diff = prev_gray ^ gray
                bit_idx = diff.bit_length() - 1
                if prev_gray & diff:
                    current -= bit_values[bit_idx]
                else:
                    current += bit_values[bit_idx]
                prev_gray = gray
            else:
                gray = 0
                prev_gray = 0
            if self.sha256_int(current) == mask.target_hash:
                for idx, pos in enumerate(unknown_positions):
                    self.known_bits[pos] = (gray >> idx) & 1
                return
        raise ValueError(f"no assignment found for mask {mask.index}")

    def solve_all(self) -> None:
        remaining = set(range(len(self.mask_bits)))
        threshold = 22
        while remaining:
            best_mask = min(
                remaining,
                key=lambda idx: sum(
                    1 for pos in self.mask_bits[idx].positions if pos not in self.known_bits
                ),
            )
            unknown = sum(
                1 for pos in self.mask_bits[best_mask].positions if pos not in self.known_bits
            )
            if unknown > threshold:
                threshold += 1
                continue
            self.solve_mask(self.mask_bits[best_mask])
            remaining.remove(best_mask)


def build_mask_structs(masks: Iterable[Tuple[int, int]], targets: List[str]) -> List[MaskData]:
    mask_bits = []
    for idx, (hex_val, shift) in enumerate(masks):
        mask = int(hex_val) << shift
        positions = []
        bit = 0
        while mask >> bit:
            if (mask >> bit) & 1:
                positions.append(bit)
            bit += 1
        mask_bits.append(MaskData(idx=idx, positions=positions, target_hash=targets[idx]))
    return mask_bits


def bits_to_bytes(bit_map: Dict[int, int], total_bytes: int) -> List[int | None]:
    res = []
    for byte_idx in range(total_bytes):
        base = 8 * (total_bytes - 1 - byte_idx)
        bits = [bit_map.get(base + offset) for offset in range(8)]
        if all(bit is not None for bit in bits):
            value = sum((bits[offset] << offset) for offset in range(8))
            res.append(value)
        else:
            res.append(None)
    return res


def fill_suffix_bits(bit_map: Dict[int, int], suffix: bytes, total_bytes: int) -> None:
    start_byte = total_bytes - len(suffix)
    for idx, byte_val in enumerate(suffix):
        byte_idx = start_byte + idx
        base = 8 * (total_bytes - 1 - byte_idx)
        for offset in range(8):
            bit_map[base + offset] = (byte_val >> offset) & 1


def candidate_chars(bits: List[int | None]) -> List[str]:
    chars = []
    for ch in ALPHABET:
        val = ord(ch)
        if all(bit is None or ((val >> offset) & 1) == bit for offset, bit in enumerate(bits)):
            chars.append(ch)
    return chars


def deduce_password(byte_values: List[int | None], bit_map: Dict[int, int]) -> str:
    total = len(byte_values)
    chars = ["?" for _ in range(total)]
    for idx, value in enumerate(byte_values):
        if value is not None:
            chars[idx] = chr(value)
    for idx, char in enumerate(chars):
        if char == "?":
            base = 8 * (total - 1 - idx)
            bits = [bit_map.get(base + offset) for offset in range(8)]
            candidates = candidate_chars(bits)
            if len(candidates) != 1:
                raise ValueError(f"ambiguous byte {idx}: {candidates}")
            chars[idx] = candidates[0]
    return "".join(chars)


def check_flag(password: str) -> str:
    body, _ = http_post("/prove-id", {"username": "admin", "password": password})
    return json.loads(body)["message"]


def main() -> None:
    print("[+] Fetching masks and admin verifier...")
    mask_pairs = fetch_masks()
    admin_b, target_hashes = fetch_admin_error()

    print("[+] Recovering prime modulus via registration oracle...")
    p = recover_prime()
    print(f"    p = {p}")

    print("[+] Solving 2-adic portion of discrete log...")
    suffix_val, pow2 = pow2_dlog(3, admin_b, p)
    suffix_bytes = suffix_val.to_bytes((pow2 + 7) // 8, "big").lstrip(b"\x00")
    print(f"    recovered suffix ({len(suffix_bytes)} bytes): {suffix_bytes.decode()}")

    total_bytes = (p.bit_length() + 7) // 8
    known_bits: Dict[int, int] = {}
    fill_suffix_bits(known_bits, suffix_bytes, total_bytes)

    print("[+] Solving mask constraints...")
    mask_structs = build_mask_structs(mask_pairs, target_hashes)
    solver = MaskSolver(mask_structs, known_bits)
    solver.solve_all()

    print("[+] Reconstructing password...")
    encrypted_bytes = bits_to_bytes(known_bits, total_bytes)
    password = deduce_password(encrypted_bytes, known_bits)
    print(f"    admin password: {password}")

    print("[+] Requesting flag...")
    flag = check_flag(password)
    print(f"    flag: {flag}")


if __name__ == "__main__":
    main()
