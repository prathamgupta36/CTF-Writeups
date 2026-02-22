# Notepad v3 : : 001 — Writeup

## Challenge Info
- **Category**: pwn
- **Points**: 100
- **Author**: Shunt
- **Service**: `nc 159.65.255.102 31226`
- **Files**: `chal` (64-bit ELF PIE)

## Summary
The binary implements a menu-driven “notepad” with add/edit/view functionality and a password check. The core bug is an **incorrect index calculation** in the edit path (`pos * 0x108`), which enables **out-of-bounds writes** on the stack. Combined with an **unchecked note size** (read length comes from user input), this allows:
1. Overwriting the canary LSB to bypass `%s` termination and leak stack data.
2. Leaking the return address to recover PIE base.
3. Overwriting the saved return address to jump into a hidden `backdoor()` function.

Because the `backdoor()` calls `execve("/bin/sh", NULL, NULL)`, the process only accepts input once; you must **pre-send** a command (e.g., `id` or `cat /flag`) immediately after the trigger.

## Binary Protections
```
RELRO:      Full
Stack:      Canary
NX:         Enabled
PIE:        Enabled
SHSTK/IBT:  Enabled
```

## Vulnerability Analysis

### Authentication
The password is stored in `.data` and compared using `strncmp` after reading 0x14 bytes:

```
password = "its a beautiful day"
```

Sending exactly **19 bytes** (no newline) makes the remaining byte a NUL, so `strncmp` succeeds.

### Add Note (size bug)
The note size is read into a stack variable and used **directly as the `read()` length**, with no upper bound relative to the actual stack buffer (0x108 bytes). This allows a huge write into the stack frame.

### Edit Note (index bug)
The edit path uses:

```
target = buffer + (pos * 0x108)
```

`pos` is **not bounded** by the number of notes. For `pos = 4`, `target` lands far beyond the note buffer and into stack metadata (canary, saved registers, return address). This gives a controlled **OOB write**.

### View Note (info leak)
The program prints the note using:

```
printf("Note: %s\n", buffer);
```

If the canary’s low byte is set to non-zero, `%s` continues past the end of the buffer and **leaks stack data** until a NUL is found.

## Exploitation Strategy

1. **Add Note** with a large size (e.g., 0x500) to allow future overwrite with `read()`.
2. **Edit pos=1** to fill the gap between the note buffer and the stack canary with non-zero bytes.
3. **Edit pos=4** with 0x39 bytes to overwrite the canary LSB (0x00 → 0x43).
4. **View Note** to leak the canary bytes.
5. **Edit pos=4** again to overwrite canary + saved regs with non-zero bytes, then:
   - **View Note** to leak the saved return address.
6. Calculate PIE base from leaked return address.
7. **Edit pos=4** again with a payload that restores the canary and overwrites the return address with `backdoor()`.
8. **Exit** to trigger the function epilogue and return into the backdoor.
9. **Pre-send a command** (e.g., `cat /flag`) because the shell is non-interactive.

## Exploit Script
The exploit is implemented in `solve.py` (included in the challenge directory). It:
- Leaks the canary
- Leaks the return address
- Computes PIE base
- Overwrites return address with `backdoor()`
- Sends a command immediately after exit

Run:
```
python3 solve.py
```
This gives shell and we can then cat the flag.

## Key Offsets
- Note buffer size: `0x108`
- Canary offset from buffer: `0x458`
- Return address offset from buffer: `0x478`
- `backdoor()` offset: from ELF symbols (PIE-relative)

## Notes
Because SHSTK/IBT is enabled, simple ret2libc is harder, but direct return to a valid function inside the PIE image (`backdoor`) still works after calculating the PIE base.

