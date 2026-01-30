from pathlib import Path
import argparse
import os
import base64
import socket

BS = 16
N_BLOCKS = 65
CHARSET = bytes(range(32, 127))

class RemoteOracle:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.file = self.sock.makefile('rwb', buffering=0)
        self._read_prompt()

    def _read_prompt(self):
        buf = b''
        while not buf.endswith(b'> '):
            ch = self.file.read(1)
            if not ch:
                raise ConnectionError('connection closed while waiting for prompt')
            buf += ch

    def query_idx(self, idx, data):
        line = f"{idx} {data.hex()}\n".encode()
        self.file.write(line)
        self.file.flush()
        resp = self.file.readline()
        if not resp:
            raise ConnectionError('connection closed')
        resp = resp.strip()
        if resp == b'error':
            raise ValueError('server returned error for query')
        try:
            blk = base64.b64decode(resp)
        except Exception as e:
            raise ValueError(f'invalid base64 response: {resp!r}') from e
        self._read_prompt()
        return blk

    def query_all(self, data):
        return [self.query_idx(i, data) for i in range(N_BLOCKS)]

class LocalOracle:
    def __init__(self):
        import importlib.util
        module_path = Path(__file__).parent / 'src' / 'server.py'
        spec = importlib.util.spec_from_file_location('server_local', module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        import os
        cwd = os.getcwd()
        try:
            os.chdir(module_path.parent)
            spec.loader.exec_module(module)  # type: ignore[attr-defined]
        finally:
            os.chdir(cwd)
        self.o = module.O()
        self.n = self.o.n

    def query_idx(self, idx, data):
        return self.o.e(idx, data)

    def query_all(self, data):
        return [self.query_idx(i, data) for i in range(self.o.n)]


def get_stable(oracle, data, tries=3):
    samples = [oracle.query_all(data) for _ in range(tries)]
    stable = {}
    for idx in range(len(samples[0])):
        val = samples[0][idx]
        if all(sample[idx] == val for sample in samples[1:]):
            stable[idx] = val
    return stable


def find_alignment(oracle):
    for pad in range(BS):
        base = b'A' * (pad + BS)
        var = b'A' * pad + b'B' + b'A' * (BS - 1)
        sb = get_stable(oracle, base)
        sv = get_stable(oracle, var)
        affected = [idx for idx in sb if idx in sv and sb[idx] != sv[idx]]
        if affected:
            print(f"[+] alignment pad {pad}, idx {affected[0]}")
            return pad, affected[0]
    raise RuntimeError('alignment failed')


def map_block(oracle, align_pad, block_num):
    blocks = [bytes([b % 256]) * BS for b in range(block_num + 1)]
    base = b'A' * align_pad + b''.join(blocks)
    alt_blocks = blocks.copy()
    alt_blocks[block_num] = bytes([(100 + block_num) % 256]) * BS
    variant = b'A' * align_pad + b''.join(alt_blocks)
    sb = get_stable(oracle, base)
    sv = get_stable(oracle, variant)
    diff = [idx for idx in sb if idx in sv and sb[idx] != sv[idx]]
    if len(diff) != 1:
        raise RuntimeError(f'could not identify block {block_num}, diffs: {diff}')
    print(f"[+] mapped block {block_num} -> idx {diff[0]}")
    return diff[0]


def recover_flag(oracle, max_len=128):
    align_pad, first_idx = find_alignment(oracle)
    block_idx_map = {0: first_idx}
    max_blocks = (256 - align_pad) // BS

    def get_block_idx(block_num):
        if block_num >= max_blocks:
            raise RuntimeError('block index exceeds controllable range')
        if block_num not in block_idx_map:
            block_idx_map[block_num] = map_block(oracle, align_pad, block_num)
        return block_idx_map[block_num]

    known = b''
    for i in range(max_len):
        block_num = i // BS
        offset = i % BS
        idx = get_block_idx(block_num)
        prefix_len = align_pad + (BS - 1 - offset)
        prefix = b'A' * prefix_len
        target = oracle.query_idx(idx, prefix)
        dictionary = {}
        for guess in CHARSET:
            guess_input = prefix + known + bytes([guess])
            blk = oracle.query_idx(idx, guess_input)
            dictionary.setdefault(blk, guess)
        if target not in dictionary:
            print(f"[!] no match at position {i}")
            break
        guess_byte = dictionary[target]
        known += bytes([guess_byte])
        print(f"[+] recovered byte {i}: {bytes([guess_byte])!r}")
        if known.endswith(b'}') and b'{' in known:
            break
    print(f"[+] recovered {known!r}")
    return known


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--remote', action='store_true')
    parser.add_argument('--host', default='34.186.247.84')
    parser.add_argument('--port', type=int, default=5000)
    args = parser.parse_args()

    if args.remote:
        oracle = RemoteOracle(args.host, args.port)
    else:
        oracle = LocalOracle()

    flag = recover_flag(oracle)
    try:
        text = flag.decode('utf-8', errors='replace')
    except Exception:
        text = repr(flag)
    print(text)

if __name__ == '__main__':
    main()
