#!/usr/bin/env python3

import re
import time
from typing import Optional

import requests


BASE_URL = "http://challenge.utctf.live:9382"
VALID_MULTS = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
FLAG_RE = re.compile(r"utflag\{[^}]+\}", re.I)


def generate_otp(username: str, epoch: int) -> str:
    add = epoch % 26
    mult = VALID_MULTS[epoch % 12]
    return "".join(
        chr((mult * (ord(ch) - ord("a")) + add) % 26 + ord("a"))
        for ch in username
    )


def discover_active_user(session: requests.Session) -> str:
    response = session.get(f"{BASE_URL}/urgent.txt", timeout=5)
    response.raise_for_status()

    match = re.search(r"FROM:\s*([a-z]+)", response.text, re.I)
    if not match:
        raise RuntimeError("could not recover the active username from /urgent.txt")

    return match.group(1).lower()


def try_login(session: requests.Session, username: str, epoch: int) -> bool:
    response = session.post(
        f"{BASE_URL}/auth",
        json={"username": username, "otp": generate_otp(username, epoch)},
        timeout=5,
        headers={"Connection": "close"},
    )
    return response.status_code == 200


def fetch_flag(session: requests.Session) -> Optional[str]:
    response = session.get(f"{BASE_URL}/portal", timeout=5, headers={"Connection": "close"})
    response.raise_for_status()

    match = FLAG_RE.search(response.text)
    return match.group(0) if match else None


def main() -> None:
    username = discover_active_user(requests.Session())
    now = int(time.time())

    for epoch in range(now - 15, now + 16):
        session = requests.Session()
        if not try_login(session, username, epoch):
            continue

        flag = fetch_flag(session)
        if not flag:
            raise RuntimeError("login succeeded but no flag was found in /portal")

        print(f"username: {username}")
        print(f"epoch: {epoch}")
        print(f"otp: {generate_otp(username, epoch)}")
        print(f"flag: {flag}")
        return

    raise RuntimeError("failed to authenticate within the expected time window")


if __name__ == "__main__":
    main()
