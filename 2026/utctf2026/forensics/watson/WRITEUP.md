# Watson Write-up

## Challenge Summary

- Category: Forensics
- Challenge: `Watson`
- Goal: answer two checkpoint questions from the provided KAPE triage, use each answer as a ZIP password, then combine the recovered checkpoint strings into the final flag.

The challenge files in the working directory were:

- `briefing.txt`
- `how-to-solve.txt`
- `checkpointA.zip`
- `checkpointB.zip`

The briefing asked for:

1. Checkpoint A: recover a deleted Word document and submit the **project name**
2. Checkpoint B: identify a suspicious installed program and submit the **SHA1 hash of the executable**

The challenge also gave two important hints:

- Checkpoint A's password is strictly uppercase
- Checkpoint B's password is the SHA1 hash

The final flag format was:

```text
utflag{checkpointA-checkpointB}
```

## Initial Triage

I started by enumerating the local files and reading the challenge text:

```bash
rg --files
sed -n '1,200p' briefing.txt
sed -n '1,200p' how-to-solve.txt
unzip -l checkpointA.zip
unzip -l checkpointB.zip
```

Then I downloaded the triage archive referenced in `DESCRIPTION.md`:

```bash
curl -L -o Modified_KAPE_Triage_Files.zip \
  https://cdn.utctf.live/Modified_KAPE_Triage_Files.zip
mkdir -p triage
unzip -q -n Modified_KAPE_Triage_Files.zip -d triage
```

The most interesting early artifacts were under the recycle bin:

- `triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/.../$R07YGFU.docx`
- `triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/.../$I07YGFU.docx`
- `triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/.../$RNJXINC.exe`
- `triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/.../$RZ7G627.exe`

Those strongly suggested a deleted document plus deleted executables, which lined up with the two checkpoint prompts.

## Checkpoint A

### Step 1: Inspect the deleted DOCX metadata

The recycle bin `$I*` file contains original filename and path metadata. Dumping it immediately showed the original document location:

```bash
xxd 'triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-47857934-2514792372-2285641962-500/$I07YGFU.docx' | sed -n '1,40p'
```

Relevant decoded path:

```text
C:\Users\Administrator\Documents\SuperSecretFolder\SuperSecretProject.docx
```

### Step 2: Extract text from the deleted DOCX

The actual deleted Word document was still present as `$R07YGFU.docx`. Reading `word/document.xml` exposed the title text directly:

```bash
unzip -p \
  'triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-47857934-2514792372-2285641962-500/$R07YGFU.docx' \
  word/document.xml | sed 's/></>\n</g' | sed -n '1,120p'
```

Key content:

```text
TOP SECRET // OMEGA COMPARTMENT
PROJECT HOOKEM
Strategic Intelligence Memorandum
```

This answered the prompt: the project name was **HOOKEM**.

The briefing said the password for Checkpoint A was strictly uppercase, so I tested the obvious candidate:

```bash
unzip -P HOOKEM -p checkpointA.zip 'Checkpoint A/A.txt'
```

Output:

```text
pr1v473_3y3
```

So:

- Checkpoint A answer: `HOOKEM`
- Checkpoint A fragment: `pr1v473_3y3`

## Checkpoint B

Checkpoint B took more work because the first obvious executables were a trap.

### Step 1: Investigate the deleted EXEs in the recycle bin

The recycle bin metadata identified two deleted executables:

```bash
xxd 'triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-47857934-2514792372-2285641962-500/$INJXINC.exe' | sed -n '1,20p'
xxd 'triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-47857934-2514792372-2285641962-500/$IZ7G627.exe' | sed -n '1,20p'
```

They mapped to:

- `C:\Users\Administrator\Downloads\VSCodeUserSetup-x64-1.111.0.exe`
- `C:\Users\Administrator\Downloads\velociraptor-v0.75.2-windows-amd64.exe`

Their SHA1 hashes were:

```bash
sha1sum \
  'triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-47857934-2514792372-2285641962-500/$RNJXINC.exe' \
  'triage/Modified_KAPE_Triage_Files/C/$Recycle.Bin/S-1-5-21-47857934-2514792372-2285641962-500/$RZ7G627.exe'
```

Results:

```text
5f07b4cc3f27a1b6048854e38e70e164861f7bf1  $RNJXINC.exe
85f85356b74f225da40ec95fab212d106345980e  $RZ7G627.exe
```

Both were plausible, especially Velociraptor, because browser artifacts showed searches for Velociraptor and even access to a local Velociraptor web UI at `https://localhost:8889`.

However, neither hash opened `checkpointB.zip`.

That meant the challenge wanted a different executable.

### Step 2: Pivot into browser and recent-file artifacts

The following artifacts were especially useful:

- `triage/Modified_KAPE_Triage_Files/C/Users/Administrator/AppData/Roaming/Mozilla/Firefox/Profiles/i387g3w0.default-release/places.sqlite`
- `triage/Modified_KAPE_Triage_Files/C/Users/Administrator/AppData/Roaming/Mozilla/Firefox/Profiles/i387g3w0.default-release/sessionstore.jsonlz4`
- `triage/Modified_KAPE_Triage_Files/C/Users/Administrator/AppData/Roaming/Microsoft/Windows/Recent/ithqsu.lnk`

The Firefox profile contained references to:

- `https://files.catbox.moe/2j40g2.zip`
- `https://files.catbox.moe/neuwhc.zip`
- `https://files.catbox.moe/ithqsu.zip`

The recent-items link `ithqsu.lnk` showed that `Administrator` had a local file:

```text
C:\Users\Administrator\Downloads\ithqsu.zip
```

This was the missing connection: there was another downloaded archive beyond the recycled public tools.

### Step 3: Recover the Catbox-hosted ZIPs

I downloaded the referenced Catbox files directly:

```bash
curl -L -o /tmp/2j40g2.zip https://files.catbox.moe/2j40g2.zip
curl -L -o /tmp/neuwhc.zip https://files.catbox.moe/neuwhc.zip
curl -L -o /tmp/ithqsu.zip https://files.catbox.moe/ithqsu.zip
```

Their contents were:

```bash
unzip -l /tmp/2j40g2.zip
unzip -l /tmp/neuwhc.zip | sed -n '1,40p'
unzip -l /tmp/ithqsu.zip
```

Findings:

- `2j40g2.zip` contained the deleted `SuperSecretProject.docx` bundle for Checkpoint A
- `neuwhc.zip` was a large KAPE toolkit archive, unrelated to the password
- `ithqsu.zip` contained exactly one executable:

```text
2ga2pl/Calc.exe
```

### Step 4: Hash the suspicious executable

I extracted and hashed `Calc.exe`:

```bash
unzip -p /tmp/ithqsu.zip '2ga2pl/Calc.exe' > /tmp/Calc.exe
file /tmp/Calc.exe
sha1sum /tmp/Calc.exe
strings /tmp/Calc.exe | sed -n '1,80p'
```

Results:

```text
/tmp/Calc.exe: PE32+ executable (console) x86-64 Mono/.Net assembly, for MS Windows, 2 sections
67198a3ca72c49fb263f4a9749b4b79c50510155  /tmp/Calc.exe
```

The strings output showed this was not a legitimate calculator binary. It looked like a trivial .NET program masquerading as `Calc.exe`, including strings such as:

- `HelloWorld`
- `Console`
- `WriteLine`
- `HelloWorld.exe`

That is exactly the kind of suspicious executable the prompt was asking for.

### Step 5: Use the SHA1 as the Checkpoint B password

Testing the hash against the encrypted checkpoint archive worked:

```bash
unzip -P 67198a3ca72c49fb263f4a9749b4b79c50510155 \
  -p checkpointB.zip 'Checkpoint B/B.txt'
```

Output:

```text
m1551n6_l1nk
```

So:

- Checkpoint B answer: `67198a3ca72c49fb263f4a9749b4b79c50510155`
- Checkpoint B fragment: `m1551n6_l1nk`

## Final Flag

Combine the two checkpoint fragments with a hyphen:

```text
utflag{pr1v473_3y3-m1551n6_l1nk}
```

## Final Answers

- Checkpoint A password: `HOOKEM`
- Checkpoint A fragment: `pr1v473_3y3`
- Checkpoint B password: `67198a3ca72c49fb263f4a9749b4b79c50510155`
- Checkpoint B fragment: `m1551n6_l1nk`
- Flag: `utflag{pr1v473_3y3-m1551n6_l1nk}`

## Notes

- The recycled Velociraptor and VS Code installers were useful context but not the final Checkpoint B answer.
- The important pivot was correlating Firefox/Catbox artifacts with the recent-file shortcut `ithqsu.lnk`.
- `ithqsu.zip` held the actual suspicious executable used for Checkpoint B.
