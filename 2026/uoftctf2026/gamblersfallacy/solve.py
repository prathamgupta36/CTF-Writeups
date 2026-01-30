#!/usr/bin/env python3
from pwn import remote, process
import re
import hmac
import hashlib
import random
import sys


GAME_RE = re.compile(r"Game \d+: Roll: ([0-9]+), Reward: ([0-9eE\.+\-]+), Nonce: ([0-9]+), Client-Seed: ([^,]+), Server-Seed: ([0-9]+)")
BALANCE_RE = re.compile(r"Balance: ([0-9eE\.+\-]+)")
FINAL_BALANCE_RE = re.compile(r"Final Balance: ([0-9eE\.+\-]+)")


def undo_right_shift_xor(y: int, shift: int) -> int:
    x = 0
    for i in range(32):
        bit_index = 31 - i
        y_bit = (y >> bit_index) & 1
        shifted_bit_index = bit_index + shift
        shifted_bit = 0
        if shifted_bit_index < 32:
            shifted_bit = (x >> shifted_bit_index) & 1
        x_bit = y_bit ^ shifted_bit
        x |= x_bit << bit_index
    return x


def undo_left_shift_xor_mask(y: int, shift: int, mask: int) -> int:
    x = 0
    for i in range(32):
        bit_index = i
        y_bit = (y >> bit_index) & 1
        if bit_index - shift >= 0 and ((mask >> bit_index) & 1):
            shifted_bit = (x >> (bit_index - shift)) & 1
        else:
            shifted_bit = 0
        if ((mask >> bit_index) & 1):
            x_bit = y_bit ^ shifted_bit
        else:
            x_bit = y_bit
        x |= x_bit << bit_index
    return x


def untemper(y: int) -> int:
    y = undo_right_shift_xor(y, 18)
    y = undo_left_shift_xor_mask(y, 15, 0xefc60000)
    y = undo_left_shift_xor_mask(y, 7, 0x9d2c5680)
    y = undo_right_shift_xor(y, 11)
    return y & 0xffffffff


class RandCrack:
    def __init__(self):
        self.state = []
        self.rng = None

    def submit(self, value: int) -> None:
        self.state.append(untemper(value & 0xffffffff))
        if len(self.state) == 624:
            mt_state = tuple(self.state) + (624,)
            r = random.Random()
            r.setstate((3, mt_state, None))
            self.rng = r

    def ready(self) -> bool:
        return self.rng is not None

    def predict_u32(self) -> int:
        if self.rng is None:
            raise RuntimeError("Predictor not ready")
        return self.rng.getrandbits(32)


class GameClient:
    def __init__(self, tube):
        self.io = tube
        self.client_seed = "1337awesome"
        self.balance = None
        self.nonce = 0

    def read_menu(self) -> None:
        data = self.io.recvuntil(b"> ")
        text = data.decode()
        m = BALANCE_RE.search(text)
        if m:
            self.balance = float(m.group(1))
        return text

    def set_client_seed(self, new_seed: str) -> None:
        self.io.sendline(b"c")
        self.io.recvuntil(b"current seed")
        self.io.recvuntil(b": ")
        self.io.recvuntil(b"\n")
        self.io.recvuntil(b"Set custom seed: ")
        self.io.sendline(new_seed.encode())
        self.client_seed = new_seed
        self.read_menu()

    def run_gamble(self, wager: float, games: int, greed: float, confirm: str = "Y"):
        self.io.sendline(b"b")
        self.io.recvuntil(b"Wager per game")
        self.io.recvuntil(b": ")
        self.io.sendline(str(wager).encode())
        self.io.recvuntil(b"Number of games")
        self.io.recvuntil(b": ")
        self.io.sendline(str(games).encode())
        self.io.recvuntil(b"Enter your number")
        self.io.recvuntil(b": ")
        self.io.sendline(str(greed).encode())
        self.io.recvuntil(b"Do you wish to proceed? (Y/N)")
        self.io.sendline(confirm.encode())
        text = self.io.recvuntil(b"> ").decode()

        game_logs = []
        for line in text.splitlines():
            m = GAME_RE.search(line)
            if m:
                game_logs.append({
                    'roll': int(m.group(1)),
                    'reward': float(m.group(2)),
                    'nonce': int(m.group(3)),
                    'client_seed': m.group(4),
                    'server_seed': int(m.group(5)),
                })
        final_balance = None
        m = FINAL_BALANCE_RE.search(text)
        if m:
            final_balance = float(m.group(1))
        balances = BALANCE_RE.findall(text)
        if balances:
            self.balance = float(balances[-1])
        if final_balance is not None:
            self.balance = final_balance
        if game_logs:
            self.nonce = game_logs[-1]['nonce'] + 1
        return {'text': text, 'logs': game_logs, 'balance': self.balance}


def compute_roll(server_seed: int, client_seed: str, nonce: int) -> int:
    msg = f"{client_seed}-{nonce}".encode()
    sig = hmac.new(str(server_seed).encode(), msg, hashlib.sha256).hexdigest()
    index = 0
    lucky = int(sig[index * 5:index * 5 + 5], 16)
    while lucky >= 1e6:
        index += 1
        lucky = int(sig[index * 5:index * 5 + 5], 16)
        if index * 5 + 5 > 129:
            lucky = 9999
            break
    roll = round((lucky % 1e4) * 1e-2)
    return int(roll)


def gather_state(client: GameClient, predictor: RandCrack):
    # Use minimal wager to gather 624 outputs
    response = client.run_gamble(wager=1, games=624, greed=98, confirm="Y")
    if len(response['logs']) < 624:
        raise RuntimeError("Did not get enough outputs")
    for entry in response['logs']:
        predictor.submit(entry['server_seed'])
    if not predictor.ready():
        raise RuntimeError("Predictor not ready after submissions")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'local':
        tube = process(['python3', 'chall.py'])
    else:
        tube = remote('34.162.20.138', 5000)

    client = GameClient(tube)
    client.read_menu()

    predictor = RandCrack()
    gather_state(client, predictor)

    # Use predictions to reach required balance
    target_balance = 10000.0
    while client.balance is None or client.balance < target_balance:
        server_seed = predictor.predict_u32()
        roll = compute_roll(server_seed, client.client_seed, client.nonce)
        if roll > 98:
            outcome = client.run_gamble(wager=1, games=1, greed=98, confirm="Y")
            if outcome['logs']:
                actual_seed = outcome['logs'][0]['server_seed']
                if actual_seed != server_seed:
                    raise RuntimeError("Prediction mismatch during burn")
            continue
        greed = max(2, roll)
        wager = client.balance
        outcome = client.run_gamble(wager=wager, games=1, greed=greed, confirm="Y")
        if not outcome['logs']:
            raise RuntimeError("Missing game log")
        actual_seed = outcome['logs'][0]['server_seed']
        if actual_seed != server_seed:
            raise RuntimeError("Prediction mismatch")

    # buy flag
    tube.sendline(b"a")
    tube.recvuntil(b"buy flag")
    tube.recvuntil(b"> ")
    tube.sendline(b"a")
    flag_output = tube.recvline().decode().strip()
    print(flag_output)


if __name__ == '__main__':
    main()

