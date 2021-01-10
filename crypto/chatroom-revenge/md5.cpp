/*
 * Simple MD5 implementation
 *
 * Compile with: gcc -o md5 -O3 -lm md5.c
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <thread>

#include <iostream>
#include <utility>
#include <vector>

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

constexpr int kN = 19;
uint8_t X[20];

char ans[] = "4b09433eeeba9ff1db650d4c9febff91";
// char ans[] = "a3195d315604e1be1ffc5226ee0421bb";

// char ans[] = "13d4a7a7f39addec886340e6043bc7ad";
uint32_t A0, A1, A2, A3;

char B[][10] = {"01000110", "01001100", "01000001", "01000111", "01111011",
                "11100xxx", "10000xxx", "10100xxx", "11100xxx", "10100xxx",
                "10101xxx", "11100xxx", "10101xxx", "10111xxx", "11100xxx",
                "10010xxx", "10110xxx", "00111xxx", "01111101"};

int M;
std::vector<std::pair<int, int>> V;

void BruteForce(uint64_t start, uint64_t end) {
  uint32_t h0, h1, h2, h3;
  uint8_t msg[100000];
  uint8_t Y[20], Z[20];

  auto MD5 = [&h0, &h1, &h2, &h3, &msg](uint8_t *initial_msg) {
    constexpr uint32_t r[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

    // Use binary integer part of the sines of integers (in radians) as
    // constants// Initialize variables:
    constexpr uint32_t k[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
    constexpr int new_len = ((((kN + 8) / 64) + 1) * 64) - 8;
    memcpy(msg, initial_msg, kN);
    msg[kN] = 128; // write the "1" bit

    uint32_t bits_len = 8 * kN;          // note, we append the len
    memcpy(msg + new_len, &bits_len, 4); // in bits at the end of the buffer
    int offset;
    for (offset = 0; offset < new_len; offset += (512 / 8)) {

      // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
      uint32_t *w = (uint32_t *)(msg + offset);
      // Initialize hash value for this chunk:
      uint32_t a = h0;
      uint32_t b = h1;
      uint32_t c = h2;
      uint32_t d = h3;

      // Main loop:
      uint32_t i;
      for (i = 0; i < 64; i++) {

        uint32_t f, g;

        if (i < 16) {
          f = (b & c) | ((~b) & d);
          g = i;
        } else if (i < 32) {
          f = (d & b) | ((~d) & c);
          g = (5 * i + 1) % 16;
        } else if (i < 48) {
          f = b ^ c ^ d;
          g = (3 * i + 5) % 16;
        } else {
          f = c ^ (b | (~d));
          g = (7 * i) % 16;
        }

        uint32_t temp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
        a = temp;
      }

      // Add this chunk's hash to result so far:

      h0 += a;
      h1 += b;
      h2 += c;
      h3 += d;
    }
  };

  while (start < end) {
    if ((start & 1048575) == 0)
      std::cout << "s = " << start << std::endl;
    for (int i = 0; i < kN; ++i)
      Y[i] = X[i];
    for (int i = 0; i < M; ++i) {
      if (start >> i & 1) {
        Y[V[i].first] |= (1 << V[i].second);
      }
    }
    for (int i = 0; i < kN; ++i)
      Z[i] = Y[i];
    MD5(Y);
    if (h0 == A0 && h1 == A1 && h2 == A2 && h3 == A3) {
      for (int i = 0; i < kN; ++i) {
        for (int j = 7; j >= 0; --j) {
          std::cerr << (Z[i] >> j & 1);
        }
        std::cerr << "\n";
      }
      return;
    }
    start++;
  }
}

int main(int argc, char **argv) {
  for (int i = 0; i < kN; ++i) {
    for (int j = 0; j < 8; ++j) {
      if (B[i][j] == 'x') {
        // std::cerr << "i = " << i << " j = " << j << "\n";
        V.emplace_back(i, 7 - j);
      } else {
        if (B[i][j] == '1')
          X[i] |= (1 << (7 - j));
      }
    }
  }

  auto Parse = [&](int p) {
    uint32_t res = 0, v;
    for (int i = 7; i >= 0; i -= 2) {
      v = ans[i + p - 1] >= '0' && ans[i + p - 1] <= '9'
              ? ans[i + p - 1] - '0'
              : ans[i + p - 1] - 'a' + 10;
      res <<= 4;
      res |= v;
      v = ans[i + p] >= '0' && ans[i + p] <= '9' ? ans[i + p] - '0'
                                                 : ans[i + p] - 'a' + 10;
      res <<= 4;
      res |= v;
    }
    return res;
  };

  A0 = Parse(0);
  A1 = Parse(8);
  A2 = Parse(16);
  A3 = Parse(24);
  M = V.size();
  constexpr int kT = 64;
  uint64_t K = (1ULL << M) / kT;
  std::vector<std::thread> Thr(kT);
  for (int i = 0; i < kT; ++i) {
    Thr[i] = std::thread(BruteForce, i * K, (i + 1) * K);
  }
  for (int i = 0; i < kT; ++i) Thr[i].join();
  return 0;
}
