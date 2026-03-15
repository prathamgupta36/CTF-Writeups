from __future__ import annotations

import io
import subprocess
import sys
import zipfile
from itertools import cycle
from pathlib import Path


def tshark_fields(pcap: Path, display_filter: str, *fields: str) -> list[list[str]]:
    cmd = ["tshark", "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for field in fields:
        cmd.extend(["-e", field])
    output = subprocess.check_output(cmd, text=True)
    rows = []
    for line in output.splitlines():
        rows.append(line.split("\t"))
    return rows


def main() -> int:
    pcap = Path("half-awake.pcap")
    if not pcap.exists():
        print(f"missing {pcap}", file=sys.stderr)
        return 1

    key_rows = tshark_fields(pcap, "mdns", "dns.txt")
    key_hex = next((row[0].strip() for row in reversed(key_rows) if row and row[0].strip()), None)
    if not key_hex:
        print("failed to recover XOR key from mDNS", file=sys.stderr)
        return 1

    payload_rows = tshark_fields(pcap, "tcp.len>0", "tcp.payload")
    zip_blob = None
    for row in payload_rows:
        if not row or not row[0]:
            continue
        payload = bytes.fromhex(row[0])
        if len(payload) >= 7 and payload[5:7] == b"PK":
            zip_blob = payload[5:]
            break

    if zip_blob is None:
        print("failed to locate ZIP payload", file=sys.stderr)
        return 1

    with zipfile.ZipFile(io.BytesIO(zip_blob)) as archive:
        stage2 = archive.read("stage2.bin")

    key = bytes.fromhex(key_hex)
    plaintext = bytes(b ^ k for b, k in zip(stage2, cycle(key)))
    print(plaintext.decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
