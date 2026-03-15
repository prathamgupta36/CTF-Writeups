#!/usr/bin/env python3

import base64
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "freem4.zip"
ZIP_PASSWORD = b"0r4ng3_ArCh1v3_T4bSp4ce!"


def extract_nested_zip_payload(tempdir: Path) -> str:
    with zipfile.ZipFile(ARCHIVE) as zf:
        zf.extract("File2.tar", tempdir)

    current = tempdir / "File2.tar"
    while tarfile.is_tarfile(current):
        with tarfile.open(current) as tf:
            member = tf.getnames()[0]
            tf.extract(member, tempdir)
        current = tempdir / member

    with zipfile.ZipFile(current) as zf:
        whitespace = zf.read("NotaFlag.txt", ZIP_PASSWORD).decode()

    bits = [
        "".join("1" if ch == "\t" else "0" for ch in line)
        for line in whitespace.splitlines()
    ]
    return "".join(chr(int(line, 2)) for line in bits)


def main() -> None:
    tempdir = Path(tempfile.mkdtemp(prefix="silentarchive_"))
    try:
        print(extract_nested_zip_payload(tempdir))
    finally:
        shutil.rmtree(tempdir)


if __name__ == "__main__":
    main()
