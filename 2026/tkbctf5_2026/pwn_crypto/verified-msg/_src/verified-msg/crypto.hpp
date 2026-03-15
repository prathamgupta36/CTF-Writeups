#include <bitset>
#include <intx/intx.hpp>
#include <openssl/rand.h>
#include <openssl/sha.h>

using uint256 = intx::uint256;
using uint512 = intx::uint512;

static const uint256 P = intx::from_string<uint256>("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
static const uint256 A = intx::from_string<uint256>("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
static const uint256 B = intx::from_string<uint256>("0x8a4d412a0d8300d7a1e9eb5132d3053f114d9be33338726be29a010c5d80bad6");
static const uint256 N = intx::from_string<uint256>("0x48757cec19c4ef9ee451a30356c4e4985efb0b7bea2838e573bf5fc3");
static const uint256 Gx = intx::from_string<uint256>("0x5b741d2fdb5e84a9c7296ab00dd6f9793b612755ef7951bd0469f3eba390ef9a");
static const uint256 Gy = intx::from_string<uint256>("0xc552e632e0700ed72c863fd2e5189c15e31eed4a7c160537b6d11b95db3d2414");

inline uint8_t parity(const uint256 &x) { return uint8_t(x & 1); }
inline uint256 mod_add(const uint256 &a, const uint256 &b, const uint256 &m) { return intx::addmod(a, b, m); }
inline uint256 mod_sub(const uint256 &a, const uint256 &b, const uint256 &m) { return intx::addmod(a, m - b % m, m); }
inline uint256 mod_mul(const uint256 &a, const uint256 &b, const uint256 &m) { return intx::mulmod(a, b, m); }

inline uint256 mod_pow(const uint256 &base, const uint256 &exp, const uint256 &m) {
  uint256 r = 1, b = base % m, e = exp;
  for (; e; e >>= 1) {
    if (e & 1) r = mod_mul(r, b, m);
    b = mod_mul(b, b, m);
  }
  return r;
}

inline uint256 mod_inv(const uint256 &a, const uint256 &m) { return mod_pow(a, m - 2, m); }
inline uint256 sqrt_mod(const uint256 &x, const uint256 &m) { return mod_pow(x % m, (m + 1) / 4, m); }

struct point_t {
  uint256 x, y;
  bool inf;
  point_t() : x(0), y(0), inf(true) {}
  point_t(const uint256 &x_, const uint256 &y_) : x(x_), y(y_), inf(false) {}
};

inline point_t point_neg(const point_t &P_) { return P_.inf ? P_ : point_t(P_.x, P_.y == 0 ? 0 : P - P_.y); }
inline point_t point_add(const point_t &P_, const point_t &Q) {
  if (P_.inf) return Q;
  if (Q.inf) return P_;
  if (P_.x == Q.x && mod_add(P_.y, Q.y, P) == 0) return point_t();
  uint256 lam;
  if (P_.x == Q.x && P_.y == Q.y) {
    if (P_.y == 0) return point_t();
    lam = mod_mul(mod_add(mod_mul(3, mod_mul(P_.x, P_.x, P), P), A, P), mod_inv(mod_mul(2, P_.y, P), P), P);
  } else {
    lam = mod_mul(mod_sub(Q.y, P_.y, P), mod_inv(mod_sub(Q.x, P_.x, P), P), P);
  }
  uint256 x3 = mod_sub(mod_sub(mod_mul(lam, lam, P), P_.x, P), Q.x, P);
  uint256 y3 = mod_sub(mod_mul(lam, mod_sub(P_.x, x3, P), P), P_.y, P);
  return point_t(x3, y3);
}

inline point_t scalar_mult(uint256 k, point_t P_) {
  point_t R;
  for (; k; k >>= 1) {
    if (k & 1) R = point_add(R, P_);
    P_ = point_add(P_, P_);
  }
  return R;
}

struct compressed_point_t {
  uint256 x;
  uint8_t y_parity;
};

inline compressed_point_t compress(const point_t &P_) { return {P_.x, parity(P_.y)}; }
inline point_t decompress(const compressed_point_t &cp) {
  uint256 x2 = mod_mul(cp.x, cp.x, P), x3 = mod_mul(x2, cp.x, P);
  uint256 y = sqrt_mod(mod_add(mod_add(x3, mod_mul(A, cp.x, P), P), B, P), P);
  if (parity(y) != cp.y_parity) y = mod_sub(P, y, P);
  return point_t(cp.x, y);
}

struct Precomp {
  static constexpr size_t N = 32768;
  std::bitset<N> slot_state;
  compressed_point_t base;
  std::array<compressed_point_t, N> table;

  void ensure(size_t idx) {
    if (!slot_state[1]) {
      table[1] = base;
      slot_state[1] = true;
    }
    size_t last = 1;
    while (last < idx && slot_state[last + 1])
      last++;
    if (last >= idx) return;
    point_t g = decompress(base), cur = decompress(table[last]);
    while (last < idx) {
      size_t i = last + 1;
      cur = point_add(cur, g);
      slot_state[i] = true;
      table[i] = compress(cur);
      last = i;
    }
  }
  point_t pick(int digit) {
    size_t idx = size_t(abs(digit));
    ensure(idx);
    point_t pt = decompress(table[idx]);
    return digit < 0 ? point_neg(pt) : pt;
  }
  point_t fast_scalar_mult(const uint256 &k) {
    std::array<int32_t, 16> digits{};
    uint256 kk = k;
    for (int i = 0; i < 16; i++) {
      int d = int(uint16_t(kk));
      kk >>= 16;
      if (d > 32767) {
        d -= 65536;
        kk += 1;
      }
      digits[i] = d;
    }
    point_t r;
    for (int i = 15; i >= 0; i--) {
      for (int j = 0; j < 16; j++)
        r = point_add(r, r);
      if (digits[i] != 0) r = point_add(r, pick(digits[i]));
    }
    return r;
  }
} precomp;
