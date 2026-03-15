#!/usr/bin/env python3

import re
from pathlib import Path


def parse_challenge(path: Path) -> tuple[int, list[int], bytes]:
    text = path.read_text()

    modulus_match = re.search(r"m\s*=\s*(\d+)", text)
    if not modulus_match:
        raise ValueError("failed to parse modulus")
    modulus = int(modulus_match.group(1))

    outputs = []
    for index in range(1, 5):
        match = re.search(rf"output_{index}\s*=\s*(\d+)", text)
        if not match:
            raise ValueError(f"failed to parse output_{index}")
        outputs.append(int(match.group(1)))

    ciphertext_match = re.search(r"ciphertext \(hex\)\s*=\s*([0-9a-fA-F]+)", text)
    if not ciphertext_match:
        raise ValueError("failed to parse ciphertext")
    ciphertext = bytes.fromhex(ciphertext_match.group(1))

    return modulus, outputs, ciphertext


def repeated_xor(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def printable_score(data: bytes) -> int:
    return sum(32 <= byte <= 126 for byte in data)


def recover_lcg_params(modulus: int, outputs: list[int]) -> tuple[int, int]:
    x1, x2, x3, _ = outputs
    delta1 = (x2 - x1) % modulus
    delta2 = (x3 - x2) % modulus

    multiplier = (delta2 * pow(delta1, -1, modulus)) % modulus
    increment = (x2 - multiplier * x1) % modulus
    return multiplier, increment


def main() -> None:
    modulus, outputs, ciphertext = parse_challenge(Path("lcg.txt"))

    multiplier, increment = recover_lcg_params(modulus, outputs)
    x1, x2, x3, x4 = outputs

    assert (multiplier * x1 + increment) % modulus == x2
    assert (multiplier * x2 + increment) % modulus == x3
    assert (multiplier * x3 + increment) % modulus == x4

    output_5 = (multiplier * x4 + increment) % modulus

    candidates = []
    for endian in ("big", "little"):
        key = output_5.to_bytes(4, endian)
        plaintext = repeated_xor(ciphertext, key)
        candidates.append((printable_score(plaintext), endian, key, plaintext))

    _, endian, key, plaintext = max(candidates)

    print(f"a = {multiplier}")
    print(f"c = {increment}")
    print(f"output_5 = {output_5} (0x{output_5:08x})")
    print(f"selected endian = {endian}")
    print(f"key = {key.hex()}")
    print(plaintext.decode())


if __name__ == "__main__":
    main()
