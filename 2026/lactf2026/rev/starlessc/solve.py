#!/usr/bin/env python3
import struct
import sys
from collections import deque

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_REG_RIP, X86_OP_MEM, X86_OP_REG


def read_elf_segments(path):
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    e_phoff = struct.unpack_from("<Q", data, 32)[0]
    e_phentsize = struct.unpack_from("<H", data, 54)[0]
    e_phnum = struct.unpack_from("<H", data, 56)[0]
    segs = {}
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<IIQQQQQQ", data, off
        )
        if p_filesz:
            segs[p_vaddr] = data[p_offset : p_offset + p_filesz]
    return segs


def build_moves(seg_data):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    moves = {}
    for base, blob in seg_data.items():
        insns = list(md.disasm(blob, base))
        insn_by_addr = {insn.address: insn for insn in insns}
        room_moves = []
        for i, insn in enumerate(insns[:-1]):
            if insn.mnemonic != "cmp" or not insn.op_str.startswith("al,"):
                continue
            key = insn.operands[1].imm
            if key not in (ord("w"), ord("a"), ord("s"), ord("d")):
                continue
            nxt = insns[i + 1]
            if nxt.mnemonic not in ("je", "jz"):
                continue
            label = nxt.operands[0].imm
            stub = insn_by_addr.get(label)
            if not stub:
                continue
            if stub.mnemonic == "mov" and stub.op_str.startswith("eax,"):
                op1 = stub.operands[1]
                if op1.type != X86_OP_MEM or op1.mem.base != X86_REG_RIP:
                    continue
                a_addr = stub.address + stub.size + op1.mem.disp
                b_addr = None
                dest = None
                for insn2 in insns[insns.index(stub) : insns.index(stub) + 40]:
                    if insn2.mnemonic == "mov" and len(insn2.operands) == 2:
                        op0, op1 = insn2.operands
                        if op0.type == X86_OP_MEM and op0.mem.base == X86_REG_RIP and op1.type == X86_OP_REG:
                            b_addr = insn2.address + insn2.size + op0.mem.disp
                    if insn2.mnemonic == "jmp":
                        dest = insn2.operands[0].imm
                        break
                if dest is None:
                    continue
                dest_base = dest - 0xC
                room_moves.append((chr(key), a_addr, b_addr, dest_base))
        if room_moves:
            moves[base] = room_moves
    return moves


def bfs_path(seg_data, moves):
    seg_bases = set(seg_data.keys())
    tokens = frozenset([addr for addr, blob in seg_data.items() if blob[0] == 0x90])
    start = 0x67679000
    required = {
        0x6767A000,
        0x67682000,
        0x6768A000,
        0x67691000,
        0x67692000,
    }
    q = deque([(start, tokens)])
    prev = {}
    seen = set([(start, tokens)])
    while q:
        pos, tok = q.popleft()
        if required.issubset(tok):
            return reconstruct(prev, (start, tokens), (pos, tok))
        for key, a_addr, b_addr, dest in moves.get(pos, []):
            if a_addr not in seg_bases:
                continue
            new_tok = tok
            if a_addr in tok:
                if b_addr is None or b_addr not in seg_bases:
                    continue
                nt = set(tok)
                nt.discard(a_addr)
                nt.add(b_addr)
                new_tok = frozenset(nt)
            if dest not in seg_bases:
                continue
            state = (dest, new_tok)
            if state in seen:
                continue
            seen.add(state)
            prev[state] = ((pos, tok), key)
            q.append(state)
    raise RuntimeError("no path found")


def reconstruct(prev, start, end):
    path = []
    cur = end
    while cur != start:
        cur, key = prev[cur]
        path.append(key)
    return "".join(reversed(path))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "starless_c"
    seg_data = read_elf_segments(path)
    moves = build_moves(seg_data)
    seq = bfs_path(seg_data, moves)
    print(seq + "f")


if __name__ == "__main__":
    main()
