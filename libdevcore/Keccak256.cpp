/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file SHA3.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include <libdevcore/Keccak256.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace std;
using namespace dev;

namespace dev
{

namespace
{

/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
static uint8_t const rho[24] = \
	{ 1,  3,   6, 10, 15, 21,
	28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43,
	62, 18, 39, 61, 20, 44};
static uint8_t const pi[24] = \
	{10,  7, 11, 17, 18, 3,
	5, 16,  8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22,  9, 6,  1};
static uint64_t const RC[24] = \
{0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
	v = 0;            \
	REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static inline void keccakf(void* state) {
	uint64_t* a = (uint64_t*)state;
	#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
#define LITTLEENDIAN(x) swap(x)
#else
#define LITTLEENDIAN(x) (x)
#endif

  const uint64_t* data64 = (const uint64_t*) data;
  // mix data into state
  for (unsigned int i = 0; i < m_blockSize / 8; i++)
    m_hash[i] ^= LITTLEENDIAN(data64[i]);

  // re-compute state
  for (unsigned int round = 0; round < KeccakRounds; round++)
  {
    // Theta
    uint64_t coefficients[5];
    for (unsigned int i = 0; i < 5; i++)
      coefficients[i] = m_hash[i] ^ m_hash[i + 5] ^ m_hash[i + 10] ^ m_hash[i + 15] ^ m_hash[i + 20];

    for (unsigned int i = 0; i < 5; i++)
    {
      uint64_t one = coefficients[mod5(i + 4)] ^ rotateLeft(coefficients[mod5(i + 1)], 1);
      m_hash[i     ] ^= one;
      m_hash[i +  5] ^= one;
      m_hash[i + 10] ^= one;
      m_hash[i + 15] ^= one;
      m_hash[i + 20] ^= one;
    }

    // temporary
    uint64_t one;

    // Rho Pi
    uint64_t last = m_hash[1];
    one = m_hash[10]; m_hash[10] = rotateLeft(last,  1); last = one;
    one = m_hash[ 7]; m_hash[ 7] = rotateLeft(last,  3); last = one;
    one = m_hash[11]; m_hash[11] = rotateLeft(last,  6); last = one;
    one = m_hash[17]; m_hash[17] = rotateLeft(last, 10); last = one;
    one = m_hash[18]; m_hash[18] = rotateLeft(last, 15); last = one;
    one = m_hash[ 3]; m_hash[ 3] = rotateLeft(last, 21); last = one;
    one = m_hash[ 5]; m_hash[ 5] = rotateLeft(last, 28); last = one;
    one = m_hash[16]; m_hash[16] = rotateLeft(last, 36); last = one;
    one = m_hash[ 8]; m_hash[ 8] = rotateLeft(last, 45); last = one;
    one = m_hash[21]; m_hash[21] = rotateLeft(last, 55); last = one;
    one = m_hash[24]; m_hash[24] = rotateLeft(last,  2); last = one;
    one = m_hash[ 4]; m_hash[ 4] = rotateLeft(last, 14); last = one;
    one = m_hash[15]; m_hash[15] = rotateLeft(last, 27); last = one;
    one = m_hash[23]; m_hash[23] = rotateLeft(last, 41); last = one;
    one = m_hash[19]; m_hash[19] = rotateLeft(last, 56); last = one;
    one = m_hash[13]; m_hash[13] = rotateLeft(last,  8); last = one;
    one = m_hash[12]; m_hash[12] = rotateLeft(last, 25); last = one;
    one = m_hash[ 2]; m_hash[ 2] = rotateLeft(last, 43); last = one;
    one = m_hash[20]; m_hash[20] = rotateLeft(last, 62); last = one;
    one = m_hash[14]; m_hash[14] = rotateLeft(last, 18); last = one;
    one = m_hash[22]; m_hash[22] = rotateLeft(last, 39); last = one;
    one = m_hash[ 9]; m_hash[ 9] = rotateLeft(last, 61); last = one;
    one = m_hash[ 6]; m_hash[ 6] = rotateLeft(last, 20); last = one;
                      m_hash[ 1] = rotateLeft(last, 44);

    // Chi
    for (unsigned int j = 0; j < 25; j += 5)
    {
      // temporaries
      uint64_t one = m_hash[j];
      uint64_t two = m_hash[j + 1];

      m_hash[j]     ^= m_hash[j + 2] & ~two;
      m_hash[j + 1] ^= m_hash[j + 3] & ~m_hash[j + 2];
      m_hash[j + 2] ^= m_hash[j + 4] & ~m_hash[j + 3];
      m_hash[j + 3] ^=      one      & ~m_hash[j + 4];
      m_hash[j + 4] ^=      two      & ~one;
    }

    // Iota
    m_hash[0] ^= XorMasks[round];
	a[0] ^= XorMasks[round];
  }
}
	

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/

#define _(S) do { S } while (0)
#define FOR(i, ST, L, S) \
	_(for (size_t i = 0; i < L; i += ST) { S; })
#define mkapply_ds(NAME, S)                                          \
	static inline void NAME(uint8_t* dst,                              \
							uint8_t const* src,                        \
							size_t len) {                              \
		FOR(i, 1, len, S);                                               \
	}
#define mkapply_sd(NAME, S)                                          \
	static inline void NAME(uint8_t const* src,                        \
							uint8_t* dst,                              \
							size_t len) {                              \
		FOR(i, 1, len, S);                                               \
	}

mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

#define P keccakf
#define Plen 200

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
	while (L >= rate) {  \
		F(a, I, rate);     \
		P(a);              \
		I += rate;         \
		L -= rate;         \
	}

/** The sponge-based hash construction. **/
inline void hash(
	uint8_t* out,
	size_t outlen,
	uint8_t const* in,
	size_t inlen,
	size_t rate,
	uint8_t delim
)
{
	uint8_t a[Plen] = {0};
	// Absorb input.
	foldP(in, inlen, xorin);
	// Xor in the DS and pad frame.
	a[inlen] ^= delim;
	a[rate - 1] ^= 0x80;
	// Xor in the last block.
	xorin(a, in, inlen);
	// Apply P
	P(a);
	// Squeeze output.
	foldP(out, outlen, setout);
	setout(a, out, outlen);
	memset(a, 0, 200);
}

}

h256 keccak256(bytesConstRef _input)
{
	h256 output;
	// Parameters used:
	// The 0x01 is the specific padding for keccak (sha3 uses 0x06) and
	// the way the round size (or window or whatever it was) is calculated.
	// 200 - (256 / 4) is the "rate"
	hash(output.data(), output.size, _input.data(), _input.size(), 200 - (256 / 4), 0x01);
	return output;
}

}
