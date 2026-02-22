from Crypto.Util.number import getPrime, getRandomInteger
from sage.all import legendre_symbol
from solver.solver import decrypt_flag

FLAG = b'flag{fakse-flag-for-testing}'

def encrypt_flag(flag, b, p):
    ciphertext = []
    plaintext = ''.join([bin(i)[2:].zfill(8) for i in flag])
    e = 65537

    for i in plaintext:
        n = pow(b, e, p)
        if i == '1':
            ciphertext.append(n)
        else:
            n = -n % p
            ciphertext.append(n)
    return ciphertext

while True:
    p = getPrime(64)
    b = getRandomInteger(64)
    if legendre_symbol(b, p) == 1:
        ciphers = encrypt_flag(FLAG, b, p)
        if FLAG == decrypt_flag(ciphers).encode():
            print("b = ", b)
            print("p = ", p)
            print("ciphers = ", ciphers)
            break
