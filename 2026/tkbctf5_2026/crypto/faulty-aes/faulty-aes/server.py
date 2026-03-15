import inspect
import os
import hashlib
# https://github.com/boppreh/aes/blob/master/aes.py
import aes


flag = os.environ.get("FLAG", "tkbctf{dummy}")
hash_val = hashlib.sha256(flag.encode()).digest()
key, msg = hash_val[:16], hash_val[16:]

pos = int(input("pos: "))
source = bytearray(inspect.getsource(aes), "utf-8")
source[pos // 8] ^= 1 << (pos % 8)
exec(bytes(source), aes.__dict__)

print("ct:", aes.AES(key).encrypt_block(msg).hex())
if bytes.fromhex(input("hash: ")) == hash_val:
    print(flag)
else:
    print("wrong")
