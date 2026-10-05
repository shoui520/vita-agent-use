/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sha256.h"
#include <string.h>

static uint32_t rotate(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32 - n));
}

static void compress(struct vau_sha256 *s)
{
	static const uint32_t constants[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
		0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
		0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
		0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
		0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
		0xc67178f2,
	};
	uint32_t w[16], a = s->state[0], b = s->state[1], c = s->state[2], d = s->state[3],
	                e = s->state[4], f = s->state[5], g = s->state[6], h = s->state[7];

	for (unsigned i = 0; i < 16; i++) {
		const unsigned char *p = s->block + 4 * i;

		w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
	}

	for (unsigned i = 0; i < 64; i++) {
		unsigned n = i & 15;

		if (i >= 16) {
			uint32_t x = w[(i + 1) & 15], y = w[(i + 14) & 15];

			w[n] += (rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3)) + w[(i + 9) & 15] +
			        (rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10));
		}

		uint32_t t = h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) + ((e & f) ^ (~e & g)) +
		             constants[i] + w[n];
		uint32_t u = (rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));

		h = g;
		g = f;
		f = e;
		e = d + t;
		d = c;
		c = b;
		b = a;
		a = t + u;
	}

	s->state[0] += a;
	s->state[1] += b;
	s->state[2] += c;
	s->state[3] += d;
	s->state[4] += e;
	s->state[5] += f;
	s->state[6] += g;
	s->state[7] += h;
}

void vau_sha256_init(struct vau_sha256 *s)
{
	static const uint32_t initial[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};

	memset(s, 0, sizeof(*s));
	memcpy(s->state, initial, sizeof(initial));
}

void vau_sha256_update(struct vau_sha256 *s, const void *data, size_t bytes)
{
	const unsigned char *p = data;

	s->bytes += bytes;
	while (bytes) {
		size_t n = 64 - s->used;

		if (n > bytes)
			n = bytes;
		memcpy(s->block + s->used, p, n);
		s->used += (unsigned)n;
		p += n;
		bytes -= n;
		if (s->used == 64) {
			compress(s);
			s->used = 0;
		}
	}
}

void vau_sha256_finish(struct vau_sha256 *s, unsigned char digest[32])
{
	uint64_t bits = s->bytes * 8;

	s->block[s->used++] = 0x80;
	if (s->used > 56) {
		memset(s->block + s->used, 0, 64 - s->used);
		compress(s);
		s->used = 0;
	}

	memset(s->block + s->used, 0, 56 - s->used);
	for (unsigned i = 0; i < 8; i++)
		s->block[63 - i] = (unsigned char)(bits >> (8 * i));
	compress(s);
	for (unsigned i = 0; i < 32; i++)
		digest[i] = (unsigned char)(s->state[i / 4] >> (24 - 8 * (i & 3)));
	memset(s, 0, sizeof(*s));
}
