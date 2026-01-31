#!/usr/bin/env python3
import sys, socket, re, os, binascii
from hashlib import sha256

# -------------------- CRC32 linear algebra helpers --------------------
def crc32_state_update(state: int, data: bytes) -> int:
    return binascii.crc32(data, state) & 0xFFFFFFFF

def build_operator(data: bytes):
    c = crc32_state_update(0, data)
    cols = []
    for i in range(32):
        out = crc32_state_update(1 << i, data)
        cols.append(out ^ c)
    return cols, c

def cols_to_rows(cols):
    rows = [0]*32
    for c, col in enumerate(cols):
        for r in range(32):
            if (col >> r) & 1:
                rows[r] |= 1 << c
    return rows

def rows_to_cols(rows):
    cols = [0]*32
    for r, row in enumerate(rows):
        for c in range(32):
            if (row >> c) & 1:
                cols[c] |= 1 << r
    return cols

def invert_cols(cols):
    rows = cols_to_rows(cols)
    inv_rows = [1 << i for i in range(32)]
    for c in range(32):
        p = None
        for r in range(c, 32):
            if (rows[r] >> c) & 1:
                p = r; break
        if p is None:
            raise ValueError("singular matrix")
        if p != c:
            rows[c], rows[p] = rows[p], rows[c]
            inv_rows[c], inv_rows[p] = inv_rows[p], inv_rows[c]
        for r in range(32):
            if r != c and ((rows[r] >> c) & 1):
                rows[r] ^= rows[c]
                inv_rows[r] ^= inv_rows[c]
    return rows_to_cols(inv_rows)

def mat_mul_vec(cols, vec):
    out = 0; i = 0
    while vec:
        if vec & 1:
            out ^= cols[i]
        vec >>= 1; i += 1
    return out

def compose(op2, op1):
    cols2, c2 = op2
    cols1, c1 = op1
    new_cols = [mat_mul_vec(cols2, cols1[i]) for i in range(32)]
    new_c = mat_mul_vec(cols2, c1) ^ c2
    return new_cols, new_c

def recover_crc_state_from_sample(nonce: bytes, msg: bytes, tag_hex: str):
    colsN, cN = build_operator(nonce)
    colsM, cM = build_operator(msg)
    colsComb, cComb = compose((colsM, cM), (colsN, cN))   # apply nonce then msg
    inv = invert_cols(colsComb)
    t = int(tag_hex, 16)
    return mat_mul_vec(inv, t ^ cComb)

# -------------------- make bytes with chosen CRC32 --------------------
def four_byte_suffix_for_target_crc(prefix: bytes, target: int) -> bytes:
    init = binascii.crc32(prefix) & 0xFFFFFFFF
    const = crc32_state_update(init, b"\x00\x00\x00\x00")
    cols = []
    for i in range(32):
        out = crc32_state_update(init, (1 << i).to_bytes(4, "little"))
        cols.append(out ^ const)
    inv = invert_cols(cols)
    x = mat_mul_vec(inv, target ^ const)
    return x.to_bytes(4, "little")

def make_bytes_with_crc32(target: int) -> bytes:
    prefix = b"\x00"*4
    return prefix + four_byte_suffix_for_target_crc(prefix, target)

# -------------------- AES-CBC decrypt --------------------
def aes_cbc_decrypt_hex(ivct_hex: str, key: bytes) -> str:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
    except Exception:
        return "[!] Install pycryptodome: pip install pycryptodome"
    raw = bytes.fromhex(ivct_hex.strip())
    iv, ct = raw[:16], raw[16:]
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    try:
        pt = unpad(pt, 16)
    except Exception:
        pass
    return pt.decode("utf-8", "ignore")

# -------------------- net helpers --------------------
def recv_until(sock, marker: bytes) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk: break
        buf += chunk
    return buf

def parse_initial(blob: bytes):
    txt = blob.decode("utf-8", "ignore")
    # collect all "Note: ... tag is XX with nonce YY."
    notes = []
    for m in re.finditer(r"tag is\s*([0-9a-fA-F]{8})\s*with nonce\s*([0-9a-fA-F]{8})", txt):
        pre = txt[:m.start()]
        p2 = pre.rfind("\n")
        p1 = pre.rfind("\n", 0, p2) if p2 != -1 else -1
        line = pre[p1+1:p2].rstrip("\r")
        msg = (line + "\n").encode()
        notes.append((msg, bytes.fromhex(m.group(2)), m.group(1)))
    mlist = re.search(r"\[([0-9,\s]+)\]", txt)
    if not mlist:
        raise RuntimeError("did not find the four CRC32 reminders")
    targets = [int(x.strip()) for x in mlist.group(1).split(",") if x.strip()]
    return notes, targets

def disambiguate_newline(notes):
    scores = []
    candidates = []
    for include_nl in (True, False):
        msg, nonce, tag = notes[0]
        msgb = msg if include_nl else msg.rstrip(b"\n")
        sK = recover_crc_state_from_sample(nonce, msgb, tag)
        ok = 0
        for m2, n2, t2 in notes:
            m2b = m2 if include_nl else m2.rstrip(b"\n")
            pred = crc32_state_update(crc32_state_update(sK, n2), m2b)
            ok += (f"{pred:08x}" == t2.lower())
        scores.append(ok); candidates.append((include_nl, sK))
    return candidates[0] if scores[0] >= scores[1] else candidates[1]

# -------------------- main --------------------
def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} HOST PORT"); sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])

    # try both payload shapes: (nonce||parts) vs (parts)
    for include_nonce_in_payload in (True, False):
        try:
            with socket.create_connection((host, port), timeout=8) as s:
                blob = recv_until(s, b"Part 1 (hex):")
                notes, targets = parse_initial(blob)
                include_nl, sK = disambiguate_newline(notes)

                parts = [make_bytes_with_crc32(t) for t in targets]
                key = sha256(b"".join(parts)).digest()
                parts_hex = [p.hex() for p in parts]

                # send the parts
                s.sendall(parts_hex[0].encode()+b"\n"); recv_until(s, b"Part 2 (hex):")
                s.sendall(parts_hex[1].encode()+b"\n"); recv_until(s, b"Part 3 (hex):")
                s.sendall(parts_hex[2].encode()+b"\n"); recv_until(s, b"Part 4 (hex):")
                s.sendall(parts_hex[3].encode()+b"\n")

                # auth step
                recv_until(s, b"nonce (hex):")
                my_nonce = os.urandom(4)
                s.sendall(my_nonce.hex().encode()+b"\n")

                recv_until(s, b"tag of the concatenation")
                # tag = CRC(key || nonce || message), message = (nonce?)+parts
                payload = (my_nonce if include_nonce_in_payload else b"") + b"".join(parts)
                tag = crc32_state_update(crc32_state_update(sK, my_nonce), payload)
                s.sendall(f"{tag:08x}".encode()+b"\n")

                # read server answer (may include "Invalid tag!" or the reward)
                text = s.recv(4096).decode("utf-8", "ignore")
                print(text, end="")  # show transcript

                # if tag rejected, retry with other payload shape
                if "Invalid tag" in text:
                    raise RuntimeError("bad tag")

                # parse reward ciphertext from the success text
                m = re.search(r"reward:\s*([0-9a-fA-F]+)", text)
                if not m:
                    # sometimes comes on the next recv
                    text += s.recv(4096).decode("utf-8", "ignore")
                    print(text, end="")
                    m = re.search(r"reward:\s*([0-9a-fA-F]+)", text)
                    if not m:
                        print("\n[!] Could not find reward ciphertext.")
                        return
                ivct_hex = m.group(1)

                # decrypt the reward with our key
                flag = aes_cbc_decrypt_hex(ivct_hex, key)
                print("\n[+] Decrypted flag:", flag)
                return
        except Exception:
            if include_nonce_in_payload:
                continue
            raise

if __name__ == "__main__":
    main()

