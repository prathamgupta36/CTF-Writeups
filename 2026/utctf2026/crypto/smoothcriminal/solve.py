from math import prod


p = 1363402168895933073124331075716158793413739602475544713040662303260999503992311247861095036060712607168809958344896622485452229880797791800555191761456659256252204001928525518751268009081850267001
g = 223
h = 1009660566883490917987475170194560289062628664411983200474597006489640893063715494610197294704009188265361176318190659133132869144519884282668828418392494875096149757008157476595873791868761173517

# p - 1 is completely smooth, so Pohlig-Hellman applies immediately.
FACTORS = {
    2: 3,
    3: 3,
    5: 3,
    7: 2,
    11: 3,
    13: 3,
    17: 3,
    19: 1,
    23: 2,
    29: 2,
    31: 3,
    37: 2,
    41: 2,
    43: 2,
    47: 3,
    53: 3,
    59: 3,
    61: 1,
    67: 3,
    71: 2,
    73: 1,
    79: 3,
    83: 2,
    89: 3,
    97: 4,
    101: 2,
    103: 1,
    107: 2,
    109: 1,
    113: 2,
    127: 7,
    131: 2,
    137: 3,
    139: 1,
    149: 5,
    151: 1,
    157: 3,
    163: 3,
    167: 2,
    173: 3,
    179: 3,
    181: 1,
    191: 5,
    193: 1,
    197: 1,
}


def dlog_small_subgroup(base: int, target: int, order: int) -> int:
    value = 1
    for k in range(order):
        if value == target:
            return k
        value = (value * base) % p
    raise ValueError(f"discrete log not found in subgroup of order {order}")


def combine_crt(congruences: list[tuple[int, int]]) -> int:
    x = 0
    modulus = 1
    for residue, mod in congruences:
        delta = ((residue - x) * pow(modulus, -1, mod)) % mod
        x += modulus * delta
        modulus *= mod
    return x % modulus


def pohlig_hellman_prime_power(q: int, e: int) -> int:
    subgroup_generator = pow(g, (p - 1) // q, p)
    residue = 0
    for j in range(e):
        corrected = h * pow(g, -residue, p) % p
        target = pow(corrected, (p - 1) // (q ** (j + 1)), p)
        digit = dlog_small_subgroup(subgroup_generator, target, q)
        residue += digit * (q**j)
    return residue


def main() -> None:
    assert prod(q**e for q, e in FACTORS.items()) == p - 1

    congruences = []
    for q, e in FACTORS.items():
        congruences.append((pohlig_hellman_prime_power(q, e), q**e))

    x = combine_crt(congruences)
    assert pow(g, x, p) == h

    flag = x.to_bytes((x.bit_length() + 7) // 8, "big").decode()
    print(flag)


if __name__ == "__main__":
    main()
