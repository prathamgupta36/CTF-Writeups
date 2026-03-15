# Sherlockk

## Challenge

- Category: Forensics
- Files provided: `briefing.txt`, `checkpointA.zip`, `checkpointB.zip`, `checkpointC.zip`
- Shared triage set: `Modified_KAPE_Triage_Files.zip`
- Prompt summary:
  - Checkpoint A asks for the complete URL of a file downloaded from an online text storage site.
  - Checkpoint B asks for the contents of a deleted note.
  - Checkpoint C asks for the MD5 of a downloaded file enumeration script.

The challenge uses the same Windows KAPE triage set as the earlier `landfall` and `watson` challenges. Each checkpoint answer is used as the password for its encrypted zip, and each decrypted zip contains one chunk of the final flag.

## Solve Strategy

The prompt already suggests the structure:

1. Recover the three answers from the triage artifacts.
2. Use each answer as the corresponding zip password.
3. Concatenate the unlocked strings into the final flag.

Because this is a Windows desktop triage, the main evidence sources are:

- browser history databases
- recycle bin entries
- NTFS metadata artifacts like `$MFT` and `$J`
- downloaded files in the user profile

## Initial Triage

I first pulled and extracted the shared triage archive:

```bash
curl -L -o Modified_KAPE_Triage_Files.zip \
  'https://cdn.utctf.live/Modified_KAPE_Triage_Files.zip'
unzip -q -n Modified_KAPE_Triage_Files.zip -d triage
```

Useful artifacts immediately visible in the extracted tree:

- Chrome history:
  - `triage/Modified_KAPE_Triage_Files/C/Users/Administrator/AppData/Local/Google/Chrome/User Data/Default/History`
- Firefox profile:
  - `triage/Modified_KAPE_Triage_Files/C/Users/Administrator/AppData/Roaming/Mozilla/Firefox/Profiles/i387g3w0.default-release/`
- Recycle Bin:
  - `triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-47857934-2514792372-2285641962-500/`
- NTFS metadata:
  - `triage/Modified_KAPE_Triage_Files/C/$MFT`
  - `triage/Modified_KAPE_Triage_Files/C/$Extend/$J`
- Suspicious download:
  - `triage/Modified_KAPE_Triage_Files/C/Users/Administrator/Downloads/script.sh.sh`

That already matches the three checkpoint themes:

- A and C are likely browser download artifacts.
- B is likely a deleted document or resident MFT artifact.

## Checkpoint A

### Question

> The threat actor downloaded a file from a online text storage site. Can you identify the complete URL the threat actor downloaded from?

### Evidence

The Chrome `History` database for `Administrator` contains the relevant download. I queried it with Python's built-in `sqlite3` module:

```bash
python3 - <<'PY'
import sqlite3
from pathlib import Path

path = Path("triage/Modified_KAPE_Triage_Files/C/Users/Administrator/AppData/Local/Google/Chrome/User Data/Default/History")
conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
cur = conn.cursor()

for row in cur.execute("""
    select d.id,
           datetime((d.start_time/1000000)-11644473600,'unixepoch') as start,
           d.target_path,
           c.chain_index,
           c.url
    from downloads d
    left join downloads_url_chains c on d.id = c.id
    order by d.start_time desc, c.chain_index asc
"""):
    print(row)

conn.close()
PY
```

Relevant output:

```text
(16, '2026-03-12 03:59:50', 'C:\\Users\\Administrator\\Downloads\\nhy8LSzI.txt', 0, 'http://pastes.io/download/nhy8LSzI')
(16, '2026-03-12 03:59:50', 'C:\\Users\\Administrator\\Downloads\\nhy8LSzI.txt', 1, 'https://pastes.io/download/nhy8LSzI')
```

This shows a download from `pastes.io`, which matches the "online text storage site" hint.

### Important Detail

The challenge asks for the complete URL, and the exact string matters. I tested the plausible variants directly against the encrypted archive:

```bash
for p in \
  'https://pastes.io/download/nhy8LSzI' \
  'http://pastes.io/download/nhy8LSzI' \
  'https://pastes.io/nhy8LSzI' \
  'http://pastes.io/nhy8LSzI'
do
  echo "== $p =="
  unzip -P "$p" -p checkpointA.zip 'Checkpoint A/A.txt' 2>/dev/null || true
  echo
done
```

Only this password worked:

```text
http://pastes.io/download/nhy8LSzI
```

### Checkpoint A Answer

```text
http://pastes.io/download/nhy8LSzI
```

### Checkpoint A Output

```bash
unzip -P 'http://pastes.io/download/nhy8LSzI' -p checkpointA.zip 'Checkpoint A/A.txt'
```

Output:

```text
b45k3rv1ll3
```

## Checkpoint B

### Question

> The threat actor wrote a note for himself on the machine. It's been deleted now, but can you retrieve the contents of the note?

Hint:

> Checkpoint B's password consist of the listed items separated by a hyphens

### First Lead: Recycle Bin

The recycle bin contains multiple deleted text files:

```bash
python3 - <<'PY'
from pathlib import Path
import struct, datetime

base = Path("triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-47857934-2514792372-2285641962-500")
for p in sorted(base.glob("$I*")):
    data = p.read_bytes()
    ver, size, ft = struct.unpack("<QQQ", data[:24])
    n = struct.unpack("<I", data[24:28])[0]
    path = data[28:28+n*2].decode("utf-16le", errors="ignore").rstrip("\x00")
    dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft / 10)
    print(f"{p.name}: size={size} deleted={dt} path={path}")
PY
```

Relevant output:

```text
$I9W158M.txt: size=0 deleted=2026-03-12 04:01:36.895000 path=C:\Users\Administrator\Documents\Note To Self.txt
$IR5UOFV.txt: size=28 deleted=2026-03-12 04:02:58.427000 path=C:\Users\Administrator\Documents\Note.txt
```

The recycled payload for `Note.txt` contains:

```text
Password is longhornHACK123*
```

That looks tempting, but it is a false lead. It does not satisfy the hint about "listed items separated by hyphens", and it does not unlock `checkpointB.zip`.

### Real Recovery Path: Older Deleted Note in `$MFT`

Searching the NTFS metadata reveals older note filenames that do not exist as normal extracted files in the triage tree:

```bash
strings -a -el -n 4 triage/Modified_KAPE_Triage_Files/C/'$MFT' | \
  rg 'Administrator Notes|Notes.txt|Note To Self|Note.txt'
```

This exposes:

```text
Notes.txt
Administrator Notes.txt
Note To Self.txt
Note.txt
```

The critical artifact is `Administrator Notes.txt`. It appears to have resident file content inside the MFT entry, which means the text can survive even after deletion.

I dumped the surrounding bytes:

```bash
python3 - <<'PY'
from pathlib import Path

p = Path("triage/Modified_KAPE_Triage_Files/C/$MFT")
data = p.read_bytes()
needle = "Administrator Notes.txt".encode("utf-16le")
i = data.find(needle)
start = max(0, i - 200)
end = min(len(data), i + 600)
chunk = data[start:end]

for off in range(0, len(chunk), 16):
    seg = chunk[off:off+16]
    hx = " ".join(f"{b:02x}" for b in seg)
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in seg)
    print(f"{start+off:08x}  {hx:<47}  {asc}")
PY
```

Relevant portion:

```text
09d361d2  00 00 18 00 00 00 47 72 6f 63 65 72 79 20 4c 69  ......Grocery Li
09d361e2  73 74 3a 0d 0a 2d 20 4c 65 74 74 75 63 65 0d 0a  st:..- Lettuce..
09d361f2  2d 20 43 61 62 62 61 67 65 0d 0a 2d 11 00 61 72  - Cabbage..-..ar
09d36202  72 6f 74 73 78 00 ff ff ff ff 82 79 47 11 00 00  rotsx......yG...
```

The recovered text is clearly:

```text
Grocery List:
- Lettuce
- Cabbage
- Carrots
```

The third item has a corrupted byte before `arrots`, but the intended word is obvious from context, and the checkpoint hint says the password is the listed items joined with hyphens.

### Verification

I verified the interpretation directly:

```bash
unzip -P 'Lettuce-Cabbage-Carrots' -p checkpointB.zip 'Checkpoint B/B.txt'
```

Output:

```text
3l3m3n74ry
```

### Checkpoint B Answer

```text
Lettuce-Cabbage-Carrots
```

### Checkpoint B Output

```text
3l3m3n74ry
```

## Checkpoint C

### Question

> The threat actor downloaded a file enumeration script. Can you submit the MD5 Hash of that file?

### Evidence

The downloaded script is already present in the triage tree:

```text
triage/Modified_KAPE_Triage_Files/C/Users/Administrator/Downloads/script.sh.sh
```

It is a shell script and very clearly a PEAS-style enumeration script:

```bash
file triage/Modified_KAPE_Triage_Files/C/Users/Administrator/Downloads/script.sh.sh
sed -n '1,40p' triage/Modified_KAPE_Triage_Files/C/Users/Administrator/Downloads/script.sh.sh
```

The hash is trivial to compute:

```bash
md5sum triage/Modified_KAPE_Triage_Files/C/Users/Administrator/Downloads/script.sh.sh
```

Output:

```text
e86475121f231c02c4a63bd0915b9dff  triage/Modified_KAPE_Triage_Files/C/Users/Administrator/Downloads/script.sh.sh
```

### Verification

```bash
unzip -P 'e86475121f231c02c4a63bd0915b9dff' -p checkpointC.zip 'Checkpoint C/C.txt'
```

Output:

```text
4r7hur_c0n4n_d0yl3
```

### Checkpoint C Answer

```text
e86475121f231c02c4a63bd0915b9dff
```

### Checkpoint C Output

```text
4r7hur_c0n4n_d0yl3
```

## Final Flag

The three decrypted checkpoint values are:

- A: `b45k3rv1ll3`
- B: `3l3m3n74ry`
- C: `4r7hur_c0n4n_d0yl3`

Combine them with hyphens:

```text
utflag{b45k3rv1ll3-3l3m3n74ry-4r7hur_c0n4n_d0yl3}
```

## Summary

This challenge is a good reminder that:

- the exact URL string matters, including `http://` vs `https://`
- obvious plaintext in the recycle bin can be a decoy
- deleted note content can survive in resident MFT data even when the file itself is gone
- validating each hypothesis against the encrypted checkpoint zip is the fastest way to confirm the answer
