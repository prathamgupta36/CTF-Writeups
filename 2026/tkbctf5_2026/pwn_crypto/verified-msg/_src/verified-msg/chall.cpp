#include "crypto.hpp"
#include <iostream>

using namespace std;

constexpr size_t MAX_MSG = 0x8000;

void admin() { system("echo you are admin!"); }
struct VerificationState {
  uint256 private_key;
  point_t public_key;
  unsigned char buffer[MAX_MSG];
  Precomp *precomp_ptr = &precomp;
  void (*callback)(void) = admin;
} vstate;

int get_num(const char *prompt) {
  cout << prompt << flush;
  int num;
  cin >> num;
  cin.ignore();
  return num;
}
void read_bytes(void *buf, size_t len) { cin.read(reinterpret_cast<char *>(buf), len); }
void write_bytes(const void *buf, size_t len) {
  cout.write(reinterpret_cast<const char *>(buf), len);
  cout.flush();
}

int main() {
  RAND_bytes((unsigned char *)&vstate.private_key, sizeof(vstate.private_key));
  vstate.private_key = vstate.private_key % N;
  vstate.public_key = scalar_mult(vstate.private_key, point_t(Gx, Gy));

  vstate.precomp_ptr->slot_state.reset();
  vstate.precomp_ptr->base = {Gx, parity(Gy)};

  while (true) {
    int mode = get_num("1: sign, 2: verify: ");

    if (mode == 1) {
      size_t len = get_num("msg_len: ");
      if (MAX_MSG < len) continue;
      read_bytes(vstate.buffer, len);

      if (memcmp(vstate.buffer, "i'm admin", 9) == 0) {
        cout << "You can't sign admin message" << endl;
        continue;
      }

      uint256 hash, nonce;
      SHA256(vstate.buffer, len, (unsigned char *)&hash);
      hash %= N;
      RAND_bytes((unsigned char *)&nonce, sizeof(nonce));
      nonce %= N;

      point_t r = scalar_mult(nonce, decompress(vstate.precomp_ptr->base));
      uint256 s = mod_mul(mod_inv(nonce, N), mod_add(hash, mod_mul(r.x, vstate.private_key, N), N), N);

      memcpy(&vstate.buffer[len], &s, sizeof(s));
      len += sizeof(s);
      memcpy(&vstate.buffer[len], &r.x, sizeof(r.x));
      len += sizeof(r.x);

      write_bytes(vstate.buffer, min(len, MAX_MSG));
    } else if (mode == 2) {
      size_t len = get_num("msg_len: ");
      if (MAX_MSG < len) continue;

      uint256 s_val, r_val;
      read_bytes(vstate.buffer, len);
      read_bytes(&s_val, sizeof(s_val));
      read_bytes(&r_val, sizeof(r_val));

      uint256 hash;
      SHA256(vstate.buffer, len, (unsigned char *)&hash);
      hash %= N;

      uint256 s_inv = mod_inv(s_val, N);
      uint256 u1 = mod_mul(hash, s_inv, N);
      uint256 u2 = mod_mul(r_val, s_inv, N);

      point_t u1_point = vstate.precomp_ptr->fast_scalar_mult(u1);
      point_t x_point = point_add(u1_point, scalar_mult(u2, vstate.public_key));

      if (!x_point.inf && x_point.x % N == r_val % N) {
        cout << "verified!" << endl;
        if (9 <= len && memcmp(vstate.buffer, "i'm admin", 9) == 0) {
          vstate.callback();
        }
        if (16 <= len && memcmp(vstate.buffer, "give me the gift", 16) == 0) {
          cout << "gift: " << hex << (size_t)admin << endl;
        }
      } else {
        cout << "verification failed!" << endl;
      }
    }
  }
}
