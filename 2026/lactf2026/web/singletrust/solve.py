#!/usr/bin/env python3
import argparse
import base64
import http.client
import http.cookies
import os
import re
import ssl
import urllib.parse
import sys
import time


ORIG_PREFIX = b'{"tmpfile":"/tmp/pastestore/'
NEW_PREFIX = b'{"tmpfile":"/flag.txt","a":"'
SUFFIX = b'"}'


def fetch_auth_cookie(host, port, use_https):
    conn = make_conn(host, port, use_https)
    conn.request("GET", "/")
    resp = conn.getresponse()
    body = resp.read()
    set_cookie = [v for (k, v) in resp.getheaders() if k.lower() == "set-cookie"]
    conn.close()
    if not set_cookie:
        raise RuntimeError("No Set-Cookie header on initial request")
    for header in set_cookie:
        jar = http.cookies.SimpleCookie()
        jar.load(header)
        if "auth" in jar:
            val = jar["auth"].value
            val = urllib.parse.unquote(val).strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            return val
    raise RuntimeError("auth cookie missing in Set-Cookie headers")


def make_conn(host, port, use_https):
    if use_https:
        ctx = ssl.create_default_context()
        return http.client.HTTPSConnection(host, port, context=ctx, timeout=10)
    return http.client.HTTPConnection(host, port, timeout=10)


def build_modified_ciphertext(ct):
    if len(ct) < len(ORIG_PREFIX) + len(SUFFIX):
        raise RuntimeError("ciphertext length too small")
    rand_len = len(ct) - len(ORIG_PREFIX) - len(SUFFIX)
    orig = ORIG_PREFIX + (b"A" * rand_len) + SUFFIX
    new = NEW_PREFIX + (b"A" * rand_len) + SUFFIX
    if len(orig) != len(new):
        raise RuntimeError("prefix lengths mismatch")
    if len(ct) != len(orig):
        raise RuntimeError("ciphertext length unexpected")
    out = bytearray(ct)
    for i in range(len(orig)):
        if orig[i] != new[i]:
            out[i] ^= orig[i] ^ new[i]
    return bytes(out)


def tag_len_accepted(host, port, use_https, iv_b64, ct_b64, tag_bytes):
    tag_b64 = base64.b64encode(tag_bytes).decode("ascii")
    cookie = f"auth={iv_b64}.{tag_b64}.{ct_b64}"
    conn = make_conn(host, port, use_https)
    conn.request("GET", "/", headers={"Cookie": cookie})
    resp = conn.getresponse()
    body = resp.read()
    set_cookie = resp.getheader("Set-Cookie")
    conn.close()
    if set_cookie is not None:
        return False
    return b"My Pastebin App" in body


def worker_loop(host, port, use_https, iv_b64, ct_b64, start, step, tag_len):
    conn = None
    i = start
    tag_mask = (1 << (8 * tag_len)) - 1
    last_log = time.time()
    while True:
        tag = (i & tag_mask).to_bytes(tag_len, "big")
        tag_b64 = base64.b64encode(tag).decode("ascii")
        cookie = f"auth={iv_b64}.{tag_b64}.{ct_b64}"
        try:
            if conn is None:
                conn = make_conn(host, port, use_https)
            conn.request("GET", "/", headers={"Cookie": cookie})
            resp = conn.getresponse()
            body = resp.read()
            set_cookie = resp.getheader("Set-Cookie")
        except Exception:
            if conn is not None:
                conn.close()
            conn = None
            i += step
            continue

        if b"lactf{" in body:
            flag = re.search(rb"lactf\\{[^}]+\\}", body)
            if flag:
                print(flag.group(0).decode("ascii"))
            else:
                print(body.decode("ascii", errors="ignore"))
            os._exit(0)

        # Optional secondary signal: if Set-Cookie is absent, auth was valid.
        if set_cookie is None and b"lactf{" in body:
            print(body.decode("ascii", errors="ignore"))
            os._exit(0)

        now = time.time()
        if now - last_log > 5:
            print(f"[pid {os.getpid()}] last tag {i:#010x}", file=sys.stderr)
            last_log = now

        i += step


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="single-trust.chall.lac.tf")
    parser.add_argument("--https", action="store_true", default=True)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1))
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--step", type=int, default=1)
    parser.add_argument("--taglen", type=int, default=0)
    args = parser.parse_args()

    port = args.port
    if port is None:
        port = 443 if args.https else 80

    auth = fetch_auth_cookie(args.host, port, args.https)
    iv_b64, tag_b64, ct_b64 = auth.split(".")
    ct = base64.b64decode(ct_b64)
    full_tag = base64.b64decode(tag_b64)

    tag_len = args.taglen
    if tag_len == 0:
        for candidate_len in (1, 2, 3, 4):
            if candidate_len > len(full_tag):
                continue
            if tag_len_accepted(
                args.host,
                port,
                args.https,
                iv_b64,
                ct_b64,
                full_tag[:candidate_len],
            ):
                tag_len = candidate_len
                print(f"[+] accepted auth tag length: {tag_len}")
                break
        if tag_len == 0:
            tag_len = 4
            print("[!] short tag lengths rejected; defaulting to 4 bytes")
    new_ct = build_modified_ciphertext(ct)
    ct_b64 = base64.b64encode(new_ct).decode("ascii")

    step = args.step * args.workers
    for w in range(args.workers):
        start = args.start + (w * args.step)
        pid = os.fork()
        if pid == 0:
            worker_loop(
                args.host, port, args.https, iv_b64, ct_b64, start, step, tag_len
            )
            return

    for _ in range(args.workers):
        os.wait()


if __name__ == "__main__":
    main()
