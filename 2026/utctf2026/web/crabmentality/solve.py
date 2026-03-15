#!/usr/bin/env python3
import argparse
import sys
import time

import requests


BASE_URL = "http://challenge.utctf.live:5888"


def open_window(session: requests.Session) -> int | None:
    session.get(f"{BASE_URL}/", timeout=10)
    response = session.get(
        f"{BASE_URL}/getFlag",
        params={"f": "flag.txt"},
        timeout=10,
    )
    print(f"[open] {response.status_code} {response.text.strip()}", flush=True)
    if response.status_code != 202:
        return None
    return response.json()["wait_until"]


def claim_flag(session: requests.Session) -> tuple[int, str, str]:
    response = session.get(
        f"{BASE_URL}/getFlag",
        params={"f": "flag.txt"},
        timeout=10,
    )
    return (
        response.status_code,
        response.headers.get("Content-Type", ""),
        response.text.strip(),
    )


def attempt_once(buffer_seconds: int, quiet_seconds: int) -> str | None:
    print(f"[quiet] sleeping {quiet_seconds}s before a fresh attempt", flush=True)
    time.sleep(quiet_seconds)

    session = requests.Session()
    wait_until = open_window(session)
    if wait_until is None:
        return None

    while True:
        remaining = wait_until + buffer_seconds - int(time.time())
        if remaining <= 0:
            break
        print(f"[wait] {remaining}s remaining", flush=True)
        time.sleep(min(60, remaining))

    status, content_type, body = claim_flag(session)
    print(f"[claim] {status} {content_type} {body}", flush=True)

    if status == 200 and "application/json" not in content_type:
        return body
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--buffer-seconds", type=int, default=4)
    parser.add_argument("--quiet-seconds", type=int, default=310)
    parser.add_argument("--attempts", type=int, default=0, help="0 means infinite")
    args = parser.parse_args()

    attempt = 0
    while args.attempts == 0 or attempt < args.attempts:
        attempt += 1
        print(f"[attempt] {attempt}", flush=True)
        flag = attempt_once(args.buffer_seconds, args.quiet_seconds)
        if flag:
            print(f"[flag] {flag}", flush=True)
            return 0

    print("[result] no flag captured", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
