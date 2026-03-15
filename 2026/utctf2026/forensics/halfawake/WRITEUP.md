# Half Awake

## Challenge

- Category: Forensics
- Files provided: `half-awake.pcap`
- Prompt summary: suspicious lab VM traffic, with a warning that some packets are pretending to be something else

The entire challenge is contained in a very small packet capture, so the solve path is mostly about careful protocol triage and carving bytes from traffic that Wireshark initially labels as something more legitimate-looking.

## Initial Triage

The first pass was to identify what protocols were present and how much traffic existed in each conversation.

```bash
capinfos half-awake.pcap
tshark -r half-awake.pcap -q -z io,phs
tshark -r half-awake.pcap -q -z conv,tcp
tshark -r half-awake.pcap -q -z conv,udp
```

Important observations:

- Only 37 packets exist, so this is intended to be solved manually.
- There is one short HTTP conversation on `10.10.10.50:51314 -> 10.10.10.1:80`.
- There are four mDNS packets.
- There are four tiny TCP conversations to port `443`, all labeled as TLS.

That immediately matches the challenge description: some traffic likely only pretends to be TLS.

## HTTP Hint Recovery

Following the only HTTP stream exposes the built-in instructions:

```bash
tshark -r half-awake.pcap -q -z follow,tcp,ascii,0
```

The response body says:

```text
Read this slowly:
1) mDNS names are hints: alert.chunk, chef.decode, key.version
2) Not every 'TCP blob' is really what it pretends to be
3) If you find a payload that starts with PK, treat it as a file
```

This gives the solve structure directly:

1. Inspect the mDNS traffic for a key or metadata.
2. Treat the TLS-looking sessions as raw payload carriers, not as real encrypted sessions.
3. Carve any payload that begins with `PK`, because that is the ZIP local-file signature.

## mDNS Analysis

The mDNS packets are:

- `alert.chunk.local`
- `chef.decode.local`
- `key.version.local`

Dumping the mDNS details shows the useful record:

```bash
tshark -r half-awake.pcap -Y mdns -V
```

The response packet contains:

- Name: `key.version.local`
- Type: `TXT`
- TXT value: `00b7`

That value is the key material used later. The wording `key.version` is a pretty explicit pointer that this TXT record matters.

## Suspicious TLS Streams

Next, inspect the TCP payloads directly instead of trusting the dissector:

```bash
tshark -r half-awake.pcap -Y 'tcp.len>0' -T fields -e frame.number -e tcp.payload
```

Relevant payloads:

```text
15  1603030018476f6c64656e2053686f7765727320466172204561737420
20  16030300184167626f67626c6f7368696520666f7277617264696e6720
25  1603030018696e76656e746f72795f7374617475733d4f4b2e2e2e2e2e
30  160303002a636c69656e745f68656c6c6f2d6973685f62797465735f5f5f4167626f67626c6f736869655f5f5f
32  160303002072616e646f6d697a65645f746c735f7061796c6f61645f626c6f636b5f303121
34  160303002072616e646f6d697a65645f746c735f7061796c6f61645f626c6f636b5f303221
36  1503030132504b0304140000000800...
```

These all start with plausible TLS record headers:

- `16 03 03 ...` for handshake-like records
- `15 03 03 ...` for an alert-like record

But the bodies are clearly not real TLS handshake messages. Some of them decode directly into plaintext strings after the first 5 bytes. The critical one is frame `36`, whose body begins with:

```text
50 4b 03 04
```

That is the ZIP file signature. So the bytes after the 5-byte fake TLS header should be carved as a ZIP archive.

## ZIP Carving

Frame `36` contains:

- a 5-byte TLS-looking header: `15 03 03 01 32`
- followed immediately by ZIP data

So the carved file is simply:

```python
zip_bytes = payload[5:]
```

Once those bytes are saved as a ZIP and listed:

```bash
unzip -l stage2.zip
```

The archive contains:

- `stage2.bin`
- `readme.txt`

The text file says:

```text
not everything here is encrypted the same way
```

This is the last hint. It implies the second-stage blob is only partially transformed, not fully encrypted.

## Stage 2 Decode

The raw `stage2.bin` bytes are:

```text
75c366db61d07bdf34db66e861c034dc33e8738433e874df33e870c530c330d430db5fc3728663dc7d
```

At this point, the natural guess is to apply the mDNS value `00b7` as a repeating XOR key:

- byte 0 XOR `0x00`
- byte 1 XOR `0xB7`
- byte 2 XOR `0x00`
- byte 3 XOR `0xB7`
- and so on

This fits both hints:

- `key.version.local` gave `00b7`
- `half awake` suggests only half the bytes are obfuscated

Applying that alternating XOR produces:

```text
utflag{h4lf_aw4k3_s33_th3_pr0t0c0l_tr1ck}
```

You can verify the first few bytes by hand:

- `0x75 ^ 0x00 = 0x75` -> `u`
- `0xC3 ^ 0xB7 = 0x74` -> `t`
- `0x66 ^ 0x00 = 0x66` -> `f`
- `0xDB ^ 0xB7 = 0x6C` -> `l`

That already spells `utfl...`, confirming the transform is correct.

## Reproducible Solver

The repository includes [`solve.py`](/home/al/Downloads/CTF/utctf2026/forensics/halfawake/solve.py), which automates the solve:

1. Read the mDNS TXT record and recover `00b7`.
2. Scan TCP payloads for a record whose body starts with `PK`.
3. Strip the fake 5-byte TLS header.
4. Open the carved ZIP in memory.
5. Extract `stage2.bin`.
6. XOR it with the repeating key bytes `00 b7`.
7. Print the decoded flag.

Run it with:

```bash
python3 solve.py
```

## Flag

```text
utflag{h4lf_aw4k3_s33_th3_pr0t0c0l_tr1ck}
```
