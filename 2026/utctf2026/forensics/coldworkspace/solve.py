#!/usr/bin/env python3

import base64
import re
from pathlib import Path

from Crypto.Cipher import AES


ROOT = Path(__file__).resolve().parent
DUMP = ROOT / "cold-workspace.dmp"


def main() -> None:
    blob = DUMP.read_bytes()
    match = re.search(
        rb"ENCD=([A-Za-z0-9+/=]+)\x00ENCK=([A-Za-z0-9+/=]+)\x00ENCV=([A-Za-z0-9+/=]+)",
        blob,
    )
    if not match:
        raise SystemExit("failed to locate ENCD/ENCK/ENCV in the dump")

    encd, enck, encv = [part.decode() for part in match.groups()]
    ciphertext = base64.b64decode(encd)
    key = base64.b64decode(enck)
    iv = base64.b64decode(encv)

    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    pad = plaintext[-1]
    if 1 <= pad <= 16 and plaintext.endswith(bytes([pad]) * pad):
        plaintext = plaintext[:-pad]

    flag = re.search(rb"utflag\{[^}]+\}", plaintext)
    if not flag:
        raise SystemExit("decryption worked but no flag was found")

    print(flag.group().decode())


if __name__ == "__main__":
    main()
