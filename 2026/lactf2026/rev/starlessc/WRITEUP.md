# starless_c (rev) writeup

## Summary

The binary is a custom ELF with no sections and a fake entry point. It prints a short poem, installs a SIGSEGV handler, then jumps into a maze-like control-flow spread across many tiny executable pages. Each page is a room. Input characters (`w`, `a`, `s`, `d`, `f`) decide which room to jump to. A hidden condition (pages that start with `0x90`) acts like "tokens" that can be moved between rooms. You must move tokens to specific rooms so that pressing `f` finally jumps to the flag-printing code.

## Binary layout

- The file is an ELF64 with no section headers (`readelf -h`), so you need to work from program headers.
- Each `PT_LOAD` segment is a 0x1000 page mapped RWX at a fixed virtual address.
- The entry point is `0x13370000`, which contains hand-written syscall code.

## Entry stub and SIGSEGV

The entry page prints the opening text, installs a SIGSEGV handler, then jumps into the maze:

```
133700bb: b8 01 00 00 00        mov    eax, 1
133700c0: bf 01 00 00 00        mov    edi, 1
133700c5: 48 89 e6              mov    rsi, rsp
133700c8: ba 87 00 00 00        mov    edx, 0x87
133700cd: 0f 05                 syscall
...
133700fe: e9 09 8f 30 54        jmp    0x6767900c
```

The SIGSEGV handler is another blob in the entry page and prints the "Not yet" line. This is how the binary handles wrong choices.

## Room format

Every room has a dispatch loop at `room+0x0c`:

```
6767900c: 31 c0                 xor    eax, eax
6767900e: 31 ff                 xor    edi, edi
67679010: 48 89 e6              mov    rsi, rsp
67679013: ba 01 00 00 00        mov    edx, 1
67679018: 0f 05                 syscall   ; read 1 byte
6767901a: 8a 06                 mov    al, [rsi]
6767901c: 3c 0a                 cmp    al, 0x0a
6767901e: 74 ec                 je     6767900c  ; skip newlines
67679020: 3c 77                 cmp    al, 0x77  ; 'w'
67679022: 74 18                 je     6767903c
...
```

The `f` key always jumps to `0x6767a000` (base address, not the dispatch):

```
... : 3c 66                 cmp al, 0x66
... : 0f 84 80 00 00 00     je  0x676790b8
676790b8: e9 43 0f 00 00     jmp 0x6767a000
```

## Token transfer stubs

Each `w/a/s/d` branch jumps to a tiny stub. The stub checks the first byte of a page (address A). If it is `0x90`, it writes `0x88c031` to A and copies the old byte to another page (address B), effectively moving a "token".

Typical stub (from one room):

```
mov eax, dword ptr [rip + disp]   ; read 4 bytes at A
cmp al, 0x90
jne next_room
mov dword ptr [rip + disp], 0x88c031  ; write to A
mov dword ptr [rip + disp], eax       ; write to B
jmp next_room
```

A page whose first byte is `0x90` is a token. Initially, the token pages are:

```
0x67689000 0x6768a000 0x6768c000 0x6768d000 0x67694000
```

## Why `f` is special

Pressing `f` jumps to the base of `0x6767a000`, not the dispatch. That base code is part of a chain of direct jumps:

```
6767a000: 31 c0 88 00           xor eax, eax; mov [rax], al
6767a004: e9 f7 7f 00 00        jmp 0x67682000
...
67692004: e9 f7 6f 9d da        jmp 0x42069000  ; flag page
```

If a page in this chain starts with `31 c0 88 00`, it will crash by writing to NULL before it can jump. The only way to make the chain safe is to move tokens so that the required pages start with `0x90`. The minimal safe set to reach the flag chain is:

```
0x6767a000 0x67682000 0x6768a000 0x67691000 0x67692000
```

## The flag page

One of the pages (at `0x42069000`) prints a longer message and then opens and prints `flag.txt`. That page is only reachable if the token transfers enable `f` to jump into it.

## Solving strategy

1. Extract each 0x1000 segment from the file and disassemble it with `objdump -D -b binary -m i386:x86-64 --adjust-vma=ADDR`.
2. For each room, parse:
   - which input keys it accepts
   - the destination room for each key
   - the token transfer pair (A -> B) if the first byte at A is `0x90`
3. Model the system as a BFS over state `(current_room, token_set)`:
   - `token_set` is the set of pages whose first byte is `0x90`
   - A move is valid if it doesn't read or write to unmapped memory
   - If A has a token, the move transfers it to B
4. Search for a state where the required tokens exist to unlock `f` and reach the flag page.

This finds a single path of length 145. Appending `f` after the path prints the flag.

## Automated solver

I included a small solver script that parses the program headers, disassembles each room with Capstone, and runs a BFS over `(room, token_set)`.

Usage:

```
python3 solve.py ./starless_c
```

It prints the full input sequence ending in `f`.
It requires the `capstone` Python package.

## Solution input

The path (followed by `f`) is:

```
sddddswaasdwaaasdssawwdwddsawasassdddwsddwasaaaawwdwdddsawaasassdddwwdwasssaaawwdwwassdddssddwasaaawwddwdsaaawdsassddwsddwawaawasdddssawdwaaddwaaf
```

## Flag

```
lactf{starless_c_more_like_starless_0xcc}
```
