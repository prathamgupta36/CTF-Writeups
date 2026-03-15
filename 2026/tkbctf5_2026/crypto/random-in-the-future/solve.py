from pathlib import Path
import random

import galois
from Crypto.Cipher import AES


N = 624
M = 397
MATRIX_A = 0x9908B0DF
TEMPER_B = 0x9D2C5680
TEMPER_C = 0xEFC60000


def parse_output(path: Path):
    nums = []
    ciphertext = None
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or "censored" in line:
            continue
        if all(c in "0123456789abcdef" for c in line) and len(line) % 2 == 0 and any(c in "abcdef" for c in line):
            ciphertext = bytes.fromhex(line)
        else:
            nums.append(int(line))
    if len(nums) != 20 or ciphertext is None:
        raise ValueError("unexpected challenge output format")
    return nums, ciphertext


def outputs_to_chunks(nums):
    chunks = []
    a = b = 1
    for n in nums:
        words = (b + 31) // 32
        rem = b % 32
        for i in range(words):
            chunk = (n >> (32 * i)) & 0xFFFFFFFF
            chunks.append((chunk, rem if i == words - 1 and rem else 32))
        a, b = b, a + b
    return chunks


def xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]


def rshift(word, shift):
    return word[shift:] + [0] * shift if shift else word[:]


def lshift(word, shift):
    return [0] * shift + word[:-shift] if shift else word[:]


def and_mask(word, mask):
    return [bit if (mask >> i) & 1 else 0 for i, bit in enumerate(word)]


def mul_const(bitexpr, const):
    return [bitexpr if (const >> i) & 1 else 0 for i in range(32)]


def unshift_right_xor(bits, shift):
    out = [0] * 32
    for i in range(31, -1, -1):
        out[i] = bits[i] ^ (out[i + shift] if i + shift < 32 else 0)
    return out


def unshift_left_xor_mask(bits, shift, mask):
    out = [0] * 32
    for i in range(32):
        out[i] = bits[i]
        if i - shift >= 0 and (mask >> i) & 1:
            out[i] ^= out[i - shift]
    return out


def untemper_symbolic(bits):
    bits = unshift_right_xor(bits, 18)
    bits = unshift_left_xor_mask(bits, 15, TEMPER_C)
    bits = unshift_left_xor_mask(bits, 7, TEMPER_B)
    bits = unshift_right_xor(bits, 11)
    return bits


def temper_symbolic(bits):
    out = xor_words(bits, rshift(bits, 11))
    out = xor_words(out, and_mask(lshift(out, 7), TEMPER_B))
    out = xor_words(out, and_mask(lshift(out, 15), TEMPER_C))
    out = xor_words(out, rshift(out, 18))
    return out


def untemper_exact(y):
    def ur(value, shift):
        out = 0
        for i in range(31, -1, -1):
            bit = ((value >> i) & 1) ^ (((out >> (i + shift)) & 1) if i + shift < 32 else 0)
            out |= bit << i
        return out

    def ul(value, shift, mask):
        out = 0
        for i in range(32):
            bit = ((value >> i) & 1) ^ ((((out >> (i - shift)) & 1) if i - shift >= 0 else 0) & ((mask >> i) & 1))
            out |= bit << i
        return out

    y = ur(y, 18)
    y = ul(y, 15, TEMPER_C)
    y = ul(y, 7, TEMPER_B)
    y = ur(y, 11)
    return y


def next_state_symbolic(state):
    mt = [word[:] for word in state]

    def mix(a, b):
        return [b[i] if i < 31 else a[31] for i in range(32)]

    for kk in range(N - M):
        y = mix(mt[kk], mt[kk + 1])
        mt[kk] = xor_words(mt[kk + M], xor_words(rshift(y, 1), mul_const(y[0], MATRIX_A)))
    for kk in range(N - M, N - 1):
        y = mix(mt[kk], mt[kk + 1])
        mt[kk] = xor_words(mt[kk + (M - N)], xor_words(rshift(y, 1), mul_const(y[0], MATRIX_A)))
    y = mix(mt[N - 1], mt[0])
    mt[N - 1] = xor_words(mt[M - 1], xor_words(rshift(y, 1), mul_const(y[0], MATRIX_A)))
    return mt


def recover_nullspace(chunks):
    first = chunks[:624]
    second = chunks[624:907]

    var_of = {}
    inv_var = []
    var_count = 0
    for pos, (_, known_bits) in enumerate(first):
        if known_bits < 32:
            for bit in range(32 - known_bits):
                var_of[(pos, bit)] = var_count
                inv_var.append((pos, bit))
                var_count += 1

    const_bit = 1 << var_count
    coeff_mask = const_bit - 1

    def const_expr(bit):
        return const_bit if bit else 0

    def symbolic_word(value, known_bits, pos):
        bits = []
        unknown_low = 32 - known_bits
        for bit in range(32):
            if known_bits == 32:
                bits.append(const_expr((value >> bit) & 1))
            elif bit < unknown_low:
                bits.append(1 << var_of[(pos, bit)])
            else:
                bits.append(const_expr((value >> (bit - unknown_low)) & 1))
        return bits

    state0 = [untemper_symbolic(symbolic_word(value, known_bits, pos)) for pos, (value, known_bits) in enumerate(first)]
    state1 = next_state_symbolic(state0)
    outputs1 = [temper_symbolic(word) for word in state1[: len(second)]]

    rows = []
    for (observed, known_bits), sym_word in zip(second, outputs1):
        unknown_low = 32 - known_bits
        for bit in range(unknown_low, 32):
            expected = ((observed >> bit) & 1) if known_bits == 32 else ((observed >> (bit - unknown_low)) & 1)
            expr = sym_word[bit]
            rhs = expected ^ ((expr >> var_count) & 1)
            coeffs = expr & coeff_mask
            if coeffs == 0:
                if rhs != 0:
                    raise ValueError("inconsistent equations")
            else:
                rows.append(coeffs | (rhs << var_count))

    basis = {}
    for row in rows:
        cur = row
        while cur & coeff_mask:
            pivot = (cur & coeff_mask).bit_length() - 1
            if pivot not in basis:
                basis[pivot] = cur
                break
            cur ^= basis[pivot]
        else:
            if (cur >> var_count) & 1:
                raise ValueError("inconsistent system")

    pivots = sorted(basis)
    for pivot in pivots:
        row = basis[pivot]
        for other in pivots:
            if other != pivot and ((basis[other] >> pivot) & 1):
                basis[other] ^= row

    free = [i for i in range(var_count) if i not in basis]

    particular = 0
    for pivot in sorted(pivots, reverse=True):
        row = basis[pivot]
        coeffs = row & coeff_mask
        rhs = (row >> var_count) & 1
        higher = coeffs & (~((1 << (pivot + 1)) - 1) & coeff_mask)
        if (higher & particular).bit_count() & 1:
            rhs ^= 1
        if rhs:
            particular |= 1 << pivot

    null_basis = []
    for free_var in free:
        vec = 1 << free_var
        for pivot in pivots:
            if (basis[pivot] >> free_var) & 1:
                vec |= 1 << pivot
        null_basis.append(vec)

    return inv_var, particular, null_basis


def state_from_assignment(first_chunks, inv_var, assignment):
    index_of = {coord: idx for idx, coord in enumerate(inv_var)}
    state = []
    for pos, (value, known_bits) in enumerate(first_chunks):
        if known_bits == 32:
            full = value
        else:
            unknown_low = 32 - known_bits
            full = value << unknown_low
            for bit in range(unknown_low):
                if (assignment >> index_of[(pos, bit)]) & 1:
                    full |= 1 << bit
        state.append(untemper_exact(full))
    return state


def characteristic_polynomial():
    gf = galois.GF(2)
    rng = random.Random(0)
    seq = gf([(rng.getrandbits(32) >> 0) & 1 for _ in range(45000)])
    return gf, galois.berlekamp_massey(seq)


def coeff_mask_for(gf, charpoly, n):
    x = galois.Poly.Identity(gf)
    rem = pow(x, int(n), charpoly)
    coeffs = [int(c) for c in rem.coeffs[::-1]]
    coeffs += [0] * (charpoly.degree - len(coeffs))
    mask = 0
    for i, coeff in enumerate(coeffs):
        if coeff:
            mask |= 1 << i
    return mask


def key_words_from_state(state, coeff_masks, degree):
    rng = random.Random()
    rng.setstate((3, tuple(state + [624]), None))
    seq_masks = [0] * 32
    for t in range(degree):
        word = rng.getrandbits(32)
        bit = 1 << t
        for j in range(32):
            if (word >> j) & 1:
                seq_masks[j] |= bit

    out = []
    for coeff_mask in coeff_masks:
        word = 0
        for j in range(32):
            if (seq_masks[j] & coeff_mask).bit_count() & 1:
                word |= 1 << j
        out.append(word)
    return tuple(out)


def total_word_count():
    a = b = 1
    total = 0
    for _ in range(100):
        total += (b + 31) // 32
        a, b = b, a + b
    return total


def main():
    nums, ciphertext = parse_output(Path("_src/random-in-the-future/output.txt"))
    chunks = outputs_to_chunks(nums)
    first = chunks[:624]

    inv_var, particular, null_basis = recover_nullspace(chunks)
    base_state = state_from_assignment(first, inv_var, particular)

    gf, charpoly = characteristic_polynomial()
    degree = charpoly.degree
    start = total_word_count() - 624
    coeff_masks = [coeff_mask_for(gf, charpoly, start + offset) for offset in range(4)]

    base_key_words = key_words_from_state(base_state, coeff_masks, degree)
    base_key_int = sum(word << (32 * i) for i, word in enumerate(base_key_words))

    diffs = []
    for vec in null_basis:
        state = state_from_assignment(first, inv_var, particular ^ vec)
        key_words = key_words_from_state(state, coeff_masks, degree)
        diffs.append(sum((a ^ b) << (32 * i) for i, (a, b) in enumerate(zip(base_key_words, key_words))))

    active_diffs = [diff for diff in diffs if diff]

    for mask in range(1 << len(active_diffs)):
        key_int = base_key_int
        for bit, diff in enumerate(active_diffs):
            if (mask >> bit) & 1:
                key_int ^= diff
        key = key_int.to_bytes(16, "little")
        plaintext = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)

        pad = plaintext[-1]
        if pad == 0 or pad > 16 or plaintext[-pad:] != bytes([pad]) * pad:
            continue

        flag = plaintext[:-pad]
        if flag.startswith(b"tkbctf{") and flag.endswith(b"}") and all(0x20 <= c <= 0x7E for c in flag):
            print(flag.decode())
            return

    raise RuntimeError("flag not found")


if __name__ == "__main__":
    main()
