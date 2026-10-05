/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * VPK extraction and promotion follows VitaShell's package installer.
 * VitaShell is Copyright (C) 2015-2018 TheFloW, GPL-3.0.
 */

#include "package_install.h"
#include "content_sdk.h"
#include "content_runtime.h"
#include "writes_vita.h"
#include "write_journal.h"
#include "format.h"
#include "json.h"
#include "file_ops.h"
#include <stdatomic.h>

extern void *vauPafMalloc(size_t);
extern void vauPafFree(void *);
#define malloc   vauPafMalloc
#define free     vauPafFree
#define snprintf vau_snprintf

#include <psp2/io/dirent.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/sysmodule.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#define INSTALL_STAGE     "ux0:data/vita-agent-use-package"
#define INSTALL_HEAD      INSTALL_STAGE "/sce_sys/package/head.bin"
#define INSTALL_SFO       INSTALL_STAGE "/sce_sys/param.sfo"
#define INSTALL_PATH_MAX  1024
#define INSTALL_IO_BUFFER (16 * 1024)
#define INSTALL_SFO_MAX   (64 * 1024)
#define INSTALL_TOTAL_MAX UINT32_MAX

enum {
	INSTALL_ERROR_ARGUMENT     = -0x7101,
	INSTALL_ERROR_ARCHIVE      = -0x7102,
	INSTALL_ERROR_ARCHIVE_PATH = -0x7103,
	INSTALL_ERROR_ARCHIVE_TYPE = -0x7104,
	INSTALL_ERROR_ARCHIVE_SIZE = -0x7105,
	INSTALL_ERROR_SFO          = -0x7106,
	INSTALL_ERROR_TITLE_ID     = -0x7107,
	INSTALL_ERROR_MEMORY       = -0x7108,
	INSTALL_ERROR_IO           = -0x7109
};

typedef struct __attribute__((packed)) SfoHeader {
	uint32_t magic;
	uint32_t version;
	uint32_t key_offset;
	uint32_t value_offset;
	uint32_t count;
} SfoHeader;

typedef struct __attribute__((packed)) SfoEntry {
	uint16_t name_offset;

	uint8_t alignment;
	uint8_t type;
	uint32_t value_size;
	uint32_t total_size;
	uint32_t data_offset;
} SfoEntry;

#define SHA1_BLOCK_SIZE 20 // SHA1 outputs a 20 byte digest

/**************************** DATA TYPES ****************************/
typedef uint8_t BYTE;  // 8-bit byte
typedef uint32_t WORD; // 32-bit word, change to "long" for 16-bit machines

typedef struct {
	BYTE data[64];
	WORD datalen;

	unsigned long long bitlen;

	WORD state[5];
	WORD k[4];
} SHA1_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
static void sha1_init(SHA1_CTX *ctx);
static void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len);
static void sha1_final(SHA1_CTX *ctx, BYTE hash[]);

#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))

/*********************** FUNCTION DEFINITIONS ***********************/
static void sha1_transform(SHA1_CTX *ctx, const BYTE data[])
{
	WORD a, b, c, d, e, i, j, t, m[80];

	for (i = 0, j = 0; i < 16; ++i, j += 4) {
		m[i] = ((uint32_t)data[j] << 24) + ((uint32_t)data[j + 1] << 16) +
		       ((uint32_t)data[j + 2] << 8) + (data[j + 3]);
	}

	for (; i < 80; ++i) {
		m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
		m[i] = (m[i] << 1) | (m[i] >> 31);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 20; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	for (; i < 40; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	for (; i < 60; ++i) {
		t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + ctx->k[2] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	for (; i < 80; ++i) {
		t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
		e = d;
		d = c;
		c = ROTLEFT(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

static void sha1_init(SHA1_CTX *ctx)
{
	ctx->datalen  = 0;
	ctx->bitlen   = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;
	ctx->k[0]     = 0x5a827999;
	ctx->k[1]     = 0x6ed9eba1;
	ctx->k[2]     = 0x8f1bbcdc;
	ctx->k[3]     = 0xca62c1d6;
}

static void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha1_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

static void sha1_final(SHA1_CTX *ctx, BYTE hash[])
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	} else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha1_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha1_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and MD uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
	}
}

/* VitaShell's fake-package head.bin template (GPL-3.0). */
static const unsigned char vita_shell_head_bin[] = {
	0x7f, 0x50, 0x4b, 0x47, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x80, 0x00, 0x00, 0x00, 0x0b,
	0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x90, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x10,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xa6, 0x89, 0x94, 0x38, 0x19, 0xf2, 0xdd, 0x05, 0x87, 0x94, 0xb0, 0xb6, 0x7f, 0xc9, 0x30, 0x76,
	0xdc, 0x2f, 0x22, 0xf2, 0x25, 0x40, 0xc6, 0xdf, 0x94, 0xcb, 0xb7, 0x78, 0xf8, 0xa2, 0x54, 0x95,
	0x8c, 0xe6, 0xfd, 0x74, 0x81, 0x0c, 0xf7, 0x9d, 0x47, 0xb2, 0x86, 0x60, 0x3c, 0x2e, 0x00, 0xbb,
	0xa2, 0x07, 0x59, 0x51, 0xe7, 0x95, 0xa4, 0xed, 0x83, 0x50, 0x35, 0xbc, 0x65, 0x63, 0xfe, 0x70,
	0x8b, 0xab, 0x0c, 0x49, 0x73, 0x9d, 0xa3, 0xc9, 0x1f, 0x74, 0x48, 0x22, 0x70, 0x93, 0xfc, 0xe9,
	0x40, 0xca, 0x74, 0x97, 0xba, 0xf1, 0xde, 0x1c, 0xaa, 0x67, 0xb7, 0x41, 0x78, 0xd7, 0x15, 0x68,
	0x7f, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x01, 0x80,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0xe0,
	0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x02, 0x00, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x0a, 0xa2, 0xcb, 0x21, 0x8b, 0x37, 0x06, 0x2d, 0x3e, 0x05, 0xfa, 0x11, 0x72, 0x72, 0x88, 0x85,
	0xc9, 0x7b, 0x03, 0x99, 0xa0, 0x70, 0x9c, 0xf8, 0xcf, 0x9d, 0x41, 0x01, 0xd6, 0x17, 0x9f, 0xd3,
	0x57, 0x79, 0x67, 0xf9, 0xb6, 0xf8, 0x56, 0x3d, 0xca, 0xfc, 0xa1, 0x98, 0xe2, 0xc7, 0xcf, 0xd6,
	0x2e, 0x1b, 0xd6, 0x1b, 0xbe, 0x6f, 0xc1, 0x92, 0xbe, 0xe0, 0xb3, 0xc2, 0xe5, 0x65, 0x5a, 0x45,
	0xd9, 0x88, 0xb4, 0x97, 0x5e, 0x16, 0x31, 0x3d, 0xa2, 0x3e, 0x16, 0xae, 0xd4, 0xb7, 0xd5, 0x36,
	0xe3, 0xac, 0x80, 0x8f, 0x18, 0xfe, 0xad, 0x1a, 0x85, 0x20, 0xce, 0xee, 0xda, 0x5d, 0xb7, 0x95,
	0x46, 0x34, 0xcc, 0x49, 0x52, 0x09, 0xf6, 0xeb, 0xa5, 0x0a, 0xe5, 0x7c, 0xb5, 0x7f, 0xaf, 0x6f,
	0x4c, 0x06, 0x8c, 0xe4, 0xd8, 0x5a, 0x03, 0xaf, 0x92, 0x4e, 0x95, 0x5b, 0xbc, 0xe0, 0xc2, 0xac,
	0xff, 0x12, 0x95, 0x31, 0x92, 0xad, 0x06, 0xe8, 0x17, 0x2c, 0xb1, 0xdc, 0x36, 0xa4, 0xc3, 0x9b,
	0xe2, 0x3e, 0x2b, 0xec, 0x65, 0x53, 0xeb, 0x58, 0x84, 0x49, 0x09, 0x0b, 0xf4, 0xc6, 0xb4, 0x02,
	0x70, 0xf3, 0x64, 0x58, 0x75, 0x14, 0x00, 0xf8, 0x68, 0x88, 0x46, 0x7e, 0x5c, 0xbc, 0xbe, 0x8b,
	0x5f, 0xac, 0xe0, 0xe4, 0xa6, 0xf5, 0x77, 0xdd, 0xd9, 0xe5, 0xaf, 0x05, 0xf0, 0x5d, 0xae, 0x22,
	0x7f, 0xb4, 0xd1, 0x1c, 0x7f, 0xcc, 0x3e, 0x98, 0x55, 0xb9, 0x69, 0xd2, 0xd2, 0x10, 0x55, 0x45,
	0x4b, 0x3c, 0x95, 0x70, 0xb7, 0xc3, 0xdb, 0xfe, 0x23, 0xaf, 0xcd, 0x27, 0xa2, 0xd3, 0xac, 0x8c,
	0x11, 0x09, 0xbf, 0xf6, 0xb2, 0x01, 0x62, 0x09, 0xc1, 0xda, 0xfd, 0xa7, 0x47, 0xa9, 0x48, 0xf4,
	0x46, 0x26, 0x06, 0xf2, 0x76, 0x4d, 0xfe, 0x6f, 0x3f, 0x10, 0xb0, 0x1c, 0x1a, 0xde, 0x73, 0x8b,
	0x14, 0x73, 0x3c, 0x39, 0xb6, 0xc6, 0x1b, 0xa1, 0x65, 0x99, 0xb8, 0x33, 0xac, 0xb8, 0x16, 0xb4,
	0xe6, 0xa5, 0xec, 0x02, 0x0b, 0x5b, 0x70, 0x23, 0xeb, 0x24, 0x1a, 0xf7, 0x8c, 0xda, 0x55, 0x96,
	0xdd, 0x4b, 0x1c, 0x85, 0x83, 0x49, 0x01, 0xb2, 0x39, 0xbc, 0x31, 0x3b, 0xe8, 0xf1, 0x5a, 0x49,
	0xcc, 0xcf, 0x0f, 0x85, 0x5f, 0x54, 0x79, 0xe8, 0x31, 0x8d, 0x57, 0x1b, 0xb1, 0xc2, 0x93, 0x87,
	0xe2, 0xe6, 0x56, 0xcf, 0x92, 0x51, 0xfc, 0x49, 0x94, 0xcd, 0xb5, 0x04, 0x1b, 0x04, 0x47, 0xf7,
	0xb4, 0xd2, 0x67, 0x31, 0x54, 0xf0, 0xad, 0x3a, 0xd4, 0x25, 0x8c, 0xed, 0xe9, 0x9b, 0x12, 0xfc,
	0x47, 0x1c, 0xfc, 0x6e, 0x81, 0x29, 0x8b, 0x39, 0xab, 0xbb, 0xf0, 0x35, 0x00, 0x87, 0x88, 0x87,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x19, 0x67, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0,
	0x1a, 0x92, 0x07, 0x04, 0x61, 0x0c, 0x9d, 0x14, 0x55, 0x8e, 0x17, 0x74, 0xb6, 0x44, 0xd2, 0x5c,
	0x93, 0xf3, 0xc1, 0x58, 0x0f, 0x91, 0x22, 0x2f, 0xfd, 0xb4, 0x42, 0xaa, 0x64, 0xfc, 0x8a, 0xd0,
	0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x05, 0x90, 0x00, 0x00, 0x03, 0x20,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xbe, 0x9a, 0x07, 0x26, 0x1a, 0x91, 0xd6, 0x35, 0x93, 0xcd, 0x59, 0xf4, 0x13, 0x23, 0x34, 0x05,
	0x5b, 0xc4, 0xf5, 0xc3, 0x31, 0xf3, 0xf9, 0xf1, 0x7e, 0xdb, 0x7f, 0x53, 0x0f, 0x1a, 0x0a, 0x79,
	0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x0a, 0x30, 0x00, 0x00, 0x00, 0x60,
	0xc2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xc3, 0x2a, 0xa0, 0xf7, 0x3a, 0x41, 0x84, 0x7c, 0xb8, 0x66, 0x43, 0x7b, 0xca, 0xcd, 0x68, 0x5e,
	0x44, 0xab, 0xd9, 0x85, 0xc9, 0x6b, 0xad, 0x33, 0xa9, 0xbc, 0x88, 0xc6, 0x75, 0xc5, 0x23, 0x9e,
	0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x28, 0x01, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x7a, 0xfe, 0xf5, 0x79, 0x30, 0xaf, 0x76, 0xe0, 0x46, 0xfc, 0x75, 0xdf, 0x08, 0x4e, 0xb8, 0x45,
	0x3d, 0x4f, 0xcb, 0xf4, 0x3d, 0x9b, 0xfa, 0x5f, 0x61, 0x99, 0x6a, 0xde, 0x9c, 0x2e, 0x1a, 0x9c,
	0x19, 0x15, 0x10, 0x1d, 0x71, 0xe6, 0xc0, 0x5a, 0x84, 0x3d, 0x20, 0xe8, 0xae, 0x1e, 0x1c, 0x71,
	0x94, 0xee, 0xbc, 0x73, 0x4d, 0x2c, 0x46, 0xbf, 0x3c, 0xf3, 0x5b, 0x30, 0x3a, 0xc3, 0x18, 0x20,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};
static const unsigned int vita_shell_head_bin_len = 1072;

/* Only inflate is linked. These defaults keep zlib on Shell's allocator,
 * without pulling in libc's heap or configuring Shell's process allocator. */
voidpf zcalloc(voidpf opaque, unsigned items, unsigned size)
{
	(void)opaque;
	if (size && items > SIZE_MAX / size)
		return NULL;

	size_t bytes = (size_t)items * size;
	void *p      = malloc(bytes);

	if (p)
		memset(p, 0, bytes);
	return p;
}

void zcfree(voidpf opaque, voidpf pointer)
{
	(void)opaque;
	free(pointer);
}

static int installation_stopped(void)
{
	VauStopStatus status = { 0 };
	int rc               = vauInputGetStopStatus(&status);

	return rc < 0 || !status.ready || status.stopped || status.chord_held ||
	       status.observation_error;
}

static atomic_uint install_phase, install_entries;
static atomic_uint install_bytes;
static int install_destination_allowed(const char *path);

/* Fixed staging subtree only. Iterative traversal keeps a deeply nested VPK
 * from consuming one directory entry and path buffer per worker stack frame. */
static int remove_tree(const char *root)
{
	char path[INSTALL_PATH_MAX];
	size_t root_length = strlen(root);

	if (!root_length || root_length >= sizeof(path))
		return INSTALL_ERROR_ARCHIVE_PATH;

	memcpy(path, root, root_length + 1);
	for (;;) {
		if (!install_destination_allowed(path))
			return VAU_DENIED;

		SceIoStat stat = { 0 };
		int rc         = sceIoGetstat(path, &stat);

		if ((uint32_t)rc == 0x80010002u && strlen(path) == root_length)
			return 0;
		if (rc < 0)
			return rc;
		if (!SCE_S_ISDIR(stat.st_mode)) {
			rc = sceIoRemove(path);
		} else {
			int directory = sceIoDopen(path);

			if (directory < 0)
				return directory;

			SceIoDirent entry;

			do {
				memset(&entry, 0, sizeof(entry));
				rc = sceIoDread(directory, &entry);
			} while (rc > 0 && (!strcmp(entry.d_name, ".") || !strcmp(entry.d_name, "..")));

			int closed = sceIoDclose(directory);

			if (rc < 0 || closed < 0)
				return rc < 0 ? rc : closed;
			if (rc > 0) {
				if (!memchr(entry.d_name, 0, sizeof(entry.d_name)) || strchr(entry.d_name, '/') ||
				    strchr(entry.d_name, ':')) {
					return INSTALL_ERROR_ARCHIVE_PATH;
				}

				size_t used = strlen(path), name = strlen(entry.d_name);

				if (used + name + 2 > sizeof(path))
					return INSTALL_ERROR_ARCHIVE_PATH;

				path[used] = '/';
				memcpy(path + used + 1, entry.d_name, name + 1);
				continue;
			}

			rc = sceIoRmdir(path);
		}

		if (rc < 0)
			return rc;
		if (strlen(path) == root_length)
			return 0;

		char *slash = strrchr(path, '/');

		if (!slash || (size_t)(slash - path) < root_length)
			return INSTALL_ERROR_ARCHIVE_PATH;

		*slash = 0;
	}
}

static int ensure_directory(const char *path)
{
	char current[INSTALL_PATH_MAX];
	size_t length = strlen(path);

	if (length == 0 || length >= sizeof(current))
		return INSTALL_ERROR_ARCHIVE_PATH;

	memcpy(current, path, length + 1);

	for (char *cursor = strchr(current, ':'); cursor != NULL && *cursor; cursor++) {
		if (*cursor != '/')
			continue;

		*cursor = '\0';
		if (cursor > current && cursor[-1] != ':') {
			int result = sceIoMkdir(current, 0777);

			if (result < 0) {
				SceIoStat stat;

				memset(&stat, 0, sizeof(stat));
				if (sceIoGetstat(current, &stat) < 0 || !SCE_S_ISDIR(stat.st_mode)) {
					*cursor = '/';
					return result;
				}
			}
		}

		*cursor = '/';
	}

	int result = sceIoMkdir(current, 0777);

	if (result < 0) {
		SceIoStat stat;

		memset(&stat, 0, sizeof(stat));
		if (sceIoGetstat(current, &stat) < 0 || !SCE_S_ISDIR(stat.st_mode))
			return result;
	}

	return 0;
}

static int ensure_parent_directory(const char *path)
{
	char parent[INSTALL_PATH_MAX];
	size_t length = strlen(path);

	if (length == 0 || length >= sizeof(parent))
		return INSTALL_ERROR_ARCHIVE_PATH;

	memcpy(parent, path, length + 1);

	char *slash = strrchr(parent, '/');

	if (slash == NULL)
		return INSTALL_ERROR_ARCHIVE_PATH;

	*slash = '\0';
	return ensure_directory(parent);
}

static int is_safe_archive_path(const char *path)
{
	if (path == NULL || path[0] == '\0' || path[0] == '/' || path[0] == '\\' ||
	    strchr(path, ':') != NULL || strchr(path, '\\') != NULL) {
		return 0;
	}

	unsigned depth        = 0;
	const char *component = path;

	while (*component != '\0') {
		if (++depth > 24)
			return 0;

		const char *slash = strchr(component, '/');
		const char *end   = slash != NULL ? slash : component + strlen(component);
		size_t length     = (size_t)(end - component);

		if (length == 0 || (length == 1 && component[0] == '.') ||
		    (length == 2 && component[0] == '.' && component[1] == '.')) {
			return 0;
		}

		if (slash == NULL || slash[1] == '\0')
			return 1;

		component = slash + 1;
	}

	return 1;
}

static uint16_t read_le16(const uint8_t *data)
{
	return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static size_t bounded_string_length(const char *value, size_t limit)
{
	size_t length = 0;

	while (length < limit && value[length] != '\0')
		length++;
	return length;
}

static uint32_t read_le32(const uint8_t *data)
{
	return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) |
	       ((uint32_t)data[3] << 24);
}

static int read_at(SceUID file, SceOff offset, void *buffer, size_t size)
{
	if (sceIoLseek(file, offset, SCE_SEEK_SET) < 0)
		return INSTALL_ERROR_IO;

	size_t done = 0;

	while (done < size) {
		if (installation_stopped())
			return VAU_DENIED;

		int read = sceIoRead(file, (uint8_t *)buffer + done, size - done);

		if (read <= 0)
			return read < 0 ? read : INSTALL_ERROR_IO;

		done += (size_t)read;
	}

	return 0;
}

static int write_all(SceUID file, const void *buffer, size_t size)
{
	size_t done = 0;

	while (done < size) {
		int written = sceIoWrite(file, (const uint8_t *)buffer + done, size - done);

		if (written <= 0)
			return written < 0 ? written : INSTALL_ERROR_IO;

		done += (size_t)written;
	}

	return 0;
}

static int extract_zip_data(SceUID input, SceOff data_offset, uint32_t compressed_size,
                            uint32_t uncompressed_size, uint16_t method, uint32_t expected_crc,
                            const char *destination)
{
	int result = ensure_parent_directory(destination);

	if (result < 0)
		return result;

	SceUID output = sceIoOpen(destination, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);

	if (output < 0)
		return output;
	if (sceIoLseek(input, data_offset, SCE_SEEK_SET) < 0) {
		sceIoClose(output);
		sceIoRemove(destination);
		return INSTALL_ERROR_IO;
	}

	uint8_t *input_buffer  = malloc(INSTALL_IO_BUFFER);
	uint8_t *output_buffer = malloc(INSTALL_IO_BUFFER);

	if (input_buffer == NULL || output_buffer == NULL) {
		free(input_buffer);
		free(output_buffer);
		sceIoClose(output);
		sceIoRemove(destination);
		return INSTALL_ERROR_MEMORY;
	}

	uint32_t checksum        = crc32(0L, Z_NULL, 0);
	uint32_t compressed_left = compressed_size;
	uint32_t produced_total  = 0;

	if (method == 0) {
		if (compressed_size != uncompressed_size) {
			result = INSTALL_ERROR_ARCHIVE_SIZE;
		} else {
			while (compressed_left > 0) {
				if (installation_stopped()) {
					result = VAU_DENIED;
					break;
				}

				size_t chunk_size =
				        compressed_left < INSTALL_IO_BUFFER ? compressed_left : INSTALL_IO_BUFFER;
				int read = sceIoRead(input, input_buffer, chunk_size);

				if (read != (int)chunk_size) {
					result = read < 0 ? read : INSTALL_ERROR_IO;
					break;
				}

				checksum = crc32(checksum, input_buffer, chunk_size);
				result   = write_all(output, input_buffer, chunk_size);
				if (result < 0)
					break;

				compressed_left -= (uint32_t)chunk_size;
				produced_total += (uint32_t)chunk_size;
			}
		}
	} else if (method == 8) {
		z_stream stream;

		memset(&stream, 0, sizeof(stream));
		stream.zalloc = zcalloc;
		stream.zfree  = zcfree;

		int zresult = inflateInit2(&stream, -MAX_WBITS);

		if (zresult != Z_OK) {
			result = INSTALL_ERROR_ARCHIVE;
		} else {
			int finished = 0;

			while (!finished) {
				if (installation_stopped()) {
					result = VAU_DENIED;
					break;
				}

				if (stream.avail_in == 0 && compressed_left > 0) {
					size_t chunk_size = compressed_left < INSTALL_IO_BUFFER ? compressed_left
					                                                        : INSTALL_IO_BUFFER;
					int read          = sceIoRead(input, input_buffer, chunk_size);

					if (read != (int)chunk_size) {
						result = read < 0 ? read : INSTALL_ERROR_IO;
						break;
					}

					stream.next_in  = input_buffer;
					stream.avail_in = chunk_size;
					compressed_left -= (uint32_t)chunk_size;
				}

				stream.next_out  = output_buffer;
				stream.avail_out = INSTALL_IO_BUFFER;
				zresult          = inflate(&stream, Z_NO_FLUSH);

				size_t produced = INSTALL_IO_BUFFER - stream.avail_out;

				if (produced > uncompressed_size - produced_total) {
					result = INSTALL_ERROR_ARCHIVE_SIZE;
					break;
				}

				if (produced > 0) {
					checksum = crc32(checksum, output_buffer, produced);
					result   = write_all(output, output_buffer, produced);
					if (result < 0)
						break;

					produced_total += (uint32_t)produced;
				}

				if (zresult == Z_STREAM_END) {
					finished = 1;
				} else if (zresult != Z_OK ||
				           (produced == 0 && stream.avail_in == 0 && compressed_left == 0)) {
					result = INSTALL_ERROR_ARCHIVE;
					break;
				}
			}

			if (result >= 0 && (compressed_left || stream.avail_in))
				result = INSTALL_ERROR_ARCHIVE;
			inflateEnd(&stream);
		}
	} else {
		result = INSTALL_ERROR_ARCHIVE_TYPE;
	}

	free(input_buffer);
	free(output_buffer);

	int closed = sceIoClose(output);

	if (result >= 0 && closed < 0)
		result = closed;
	if (result >= 0 && (produced_total != uncompressed_size || checksum != expected_crc))
		result = INSTALL_ERROR_ARCHIVE;
	if (result < 0)
		sceIoRemove(destination);
	return result;
}

static int find_central_directory(SceUID file, SceOff file_size, uint32_t *offset,
                                  uint16_t *entry_count)
{
	/* The end-of-central-directory record (22 bytes) may be followed by a
	 * comment of up to 65535 bytes, so it lies within the last 0x10016. */
	size_t tail_size = file_size < 0x10016 ? (size_t)file_size : 0x10016;
	uint8_t *tail    = malloc(tail_size);

	if (tail == NULL)
		return INSTALL_ERROR_MEMORY;

	int result = read_at(file, file_size - tail_size, tail, tail_size);

	if (result < 0) {
		free(tail);
		return result;
	}

	result = INSTALL_ERROR_ARCHIVE;
	for (size_t index = tail_size - 22;; index--) {
		if (read_le32(tail + index) == 0x06054B50) { /* "PK\5\6" */
			uint16_t disk            = read_le16(tail + index + 4);
			uint16_t central_disk    = read_le16(tail + index + 6);
			uint16_t entries_on_disk = read_le16(tail + index + 8);
			uint16_t entries         = read_le16(tail + index + 10);
			uint32_t central_size    = read_le32(tail + index + 12);
			uint32_t central_offset  = read_le32(tail + index + 16);

			if (disk == 0 && central_disk == 0 && entries == entries_on_disk && entries != 0xFFFF &&
			    index + 22 + read_le16(tail + index + 20) == tail_size &&
			    (uint64_t)central_offset + central_size <=
			            (uint64_t)(file_size - tail_size + index)) {
				*offset      = central_offset;
				*entry_count = entries;
				result       = 0;
			}
			break;
		}

		if (index == 0)
			break;
	}

	free(tail);
	return result;
}

static int extract_vpk(const char *vpk_path)
{
	SceUID file = sceIoOpen(vpk_path, SCE_O_RDONLY, 0);

	if (file < 0)
		return file;

	SceOff file_size = sceIoLseek(file, 0, SCE_SEEK_END);

	if (file_size < 22) {
		sceIoClose(file);
		return INSTALL_ERROR_ARCHIVE;
	}

	uint32_t central_offset = 0;
	uint16_t entry_count    = 0;
	int result          = find_central_directory(file, file_size, &central_offset, &entry_count);
	uint64_t total_size = 0;
	SceOff cursor       = central_offset;

	for (uint16_t index = 0; result >= 0 && index < entry_count; index++) {
		if (installation_stopped()) {
			result = VAU_DENIED;
			break;
		}

		uint8_t central[46];

		result = read_at(file, cursor, central, sizeof(central));
		if (result < 0 || read_le32(central) != 0x02014B50) {
			result = INSTALL_ERROR_ARCHIVE;
			break;
		}

		uint16_t flags             = read_le16(central + 8);
		uint16_t method            = read_le16(central + 10);
		uint32_t expected_crc      = read_le32(central + 16);
		uint32_t compressed_size   = read_le32(central + 20);
		uint32_t uncompressed_size = read_le32(central + 24);
		uint16_t name_size         = read_le16(central + 28);
		uint16_t extra_size        = read_le16(central + 30);
		uint16_t comment_size      = read_le16(central + 32);
		uint16_t disk              = read_le16(central + 34);
		uint32_t attributes        = read_le32(central + 38);
		uint32_t local_offset      = read_le32(central + 42);
		SceOff next = cursor + sizeof(central) + name_size + extra_size + comment_size;

		/* No encryption, multi-disk or ZIP64 (0xFFFFFFFF fields); only store/deflate. */
		if ((flags & 1) || disk != 0 || name_size == 0 || name_size >= INSTALL_PATH_MAX / 2 ||
		    compressed_size == 0xFFFFFFFF || uncompressed_size == 0xFFFFFFFF ||
		    local_offset == 0xFFFFFFFF || (method != 0 && method != 8) || next > file_size) {
			result = INSTALL_ERROR_ARCHIVE;
			break;
		}

		char entry_path[INSTALL_PATH_MAX / 2];

		result = read_at(file, cursor + sizeof(central), entry_path, name_size);
		if (result < 0)
			break;

		entry_path[name_size] = '\0';
		if (memchr(entry_path, 0, name_size) || !is_safe_archive_path(entry_path)) {
			result = INSTALL_ERROR_ARCHIVE_PATH;
			break;
		}

		uint32_t unix_type = (attributes >> 16) & 0170000;
		int is_directory   = entry_path[name_size - 1] == '/';

		if (is_directory && uncompressed_size) {
			result = INSTALL_ERROR_ARCHIVE;
			break;
		}

		if (unix_type != 0 && unix_type != 0100000 && unix_type != 0040000) {
			result = INSTALL_ERROR_ARCHIVE_TYPE;
			break;
		}

		if (uncompressed_size > INSTALL_TOTAL_MAX - total_size) {
			result = INSTALL_ERROR_ARCHIVE_SIZE;
			break;
		}

		total_size += uncompressed_size;

		char destination[INSTALL_PATH_MAX];
		int length = snprintf(destination, sizeof(destination), "%s/%s", INSTALL_STAGE, entry_path);

		if (length < 0 || (size_t)length >= sizeof(destination)) {
			result = INSTALL_ERROR_ARCHIVE_PATH;
			break;
		}

		if (!install_destination_allowed(destination)) {
			result = VAU_DENIED;
			break;
		}

		SceIoStat previous = { 0 };
		int prior          = sceIoGetstat(destination, &previous);

		if (prior >= 0 && (!is_directory || !SCE_S_ISDIR(previous.st_mode))) {
			result = INSTALL_ERROR_ARCHIVE_PATH;
			break;
		}

		if (prior < 0 && (uint32_t)prior != 0x80010002u) {
			result = prior;
			break;
		}

		if (is_directory) {
			destination[length - 1] = '\0';
			result                  = ensure_directory(destination);
		} else {
			uint8_t local[30];

			result = read_at(file, local_offset, local, sizeof(local));
			if (result < 0 || read_le32(local) != 0x04034B50 || read_le16(local + 8) != method) {
				result = INSTALL_ERROR_ARCHIVE;
				break;
			}

			uint16_t local_name_size  = read_le16(local + 26);
			uint16_t local_extra_size = read_le16(local + 28);
			uint64_t data_offset =
			        (uint64_t)local_offset + sizeof(local) + local_name_size + local_extra_size;

			if (data_offset + compressed_size > (uint64_t)file_size) {
				result = INSTALL_ERROR_ARCHIVE;
				break;
			}

			result = extract_zip_data(file, data_offset, compressed_size, uncompressed_size, method,
			                          expected_crc, destination);
		}

		if (result >= 0) {
			atomic_fetch_add_explicit(&install_entries, 1, memory_order_relaxed);
			atomic_fetch_add_explicit(&install_bytes, uncompressed_size, memory_order_relaxed);
		}

		cursor = next;
	}

	sceIoClose(file);
	return result;
}

static int read_file(const char *path, void **buffer_out, size_t *size_out)
{
	SceUID file = sceIoOpen(path, SCE_O_RDONLY, 0);

	if (file < 0)
		return file;

	SceOff end = sceIoLseek(file, 0, SCE_SEEK_END);

	if (end <= 0 || end > INSTALL_SFO_MAX) {
		sceIoClose(file);
		return INSTALL_ERROR_SFO;
	}

	if (sceIoLseek(file, 0, SCE_SEEK_SET) < 0) {
		sceIoClose(file);
		return INSTALL_ERROR_IO;
	}

	void *buffer = malloc((size_t)end);

	if (buffer == NULL) {
		sceIoClose(file);
		return INSTALL_ERROR_MEMORY;
	}

	size_t offset = 0;

	while (offset < (size_t)end) {
		int read = sceIoRead(file, (char *)buffer + offset, (size_t)end - offset);

		if (read <= 0) {
			free(buffer);
			sceIoClose(file);
			return read < 0 ? read : INSTALL_ERROR_IO;
		}

		offset += (size_t)read;
	}

	sceIoClose(file);
	*buffer_out = buffer;
	*size_out   = (size_t)end;
	return 0;
}

static int sfo_string(const void *buffer, size_t size, const char *key, char *value,
                      size_t value_size)
{
	if (size < sizeof(SfoHeader) || value_size == 0)
		return INSTALL_ERROR_SFO;

	const uint8_t *bytes    = (const uint8_t *)buffer;
	const SfoHeader *header = (const SfoHeader *)buffer;

	if (header->magic != 0x46535000 || /* "\0PSF" */
	    header->count > (size - sizeof(SfoHeader)) / sizeof(SfoEntry)) {
		return INSTALL_ERROR_SFO;
	}

	const SfoEntry *entries = (const SfoEntry *)(bytes + sizeof(SfoHeader));

	for (uint32_t index = 0; index < header->count; index++) {
		uint64_t key_offset  = (uint64_t)header->key_offset + entries[index].name_offset;
		uint64_t data_offset = (uint64_t)header->value_offset + entries[index].data_offset;

		if (key_offset >= size || data_offset >= size || entries[index].value_size == 0 ||
		    entries[index].value_size > size - data_offset) {
			return INSTALL_ERROR_SFO;
		}

		size_t key_space  = size - (size_t)key_offset;
		size_t data_space = entries[index].value_size;

		if (memchr(bytes + key_offset, '\0', key_space) == NULL)
			return INSTALL_ERROR_SFO;
		if (strcmp((const char *)bytes + key_offset, key) != 0)
			continue;
		if (entries[index].type != 2 || !memchr(bytes + data_offset, 0, data_space))
			return INSTALL_ERROR_SFO;

		size_t length = bounded_string_length((const char *)bytes + data_offset, data_space);

		if (length >= value_size)
			length = value_size - 1;
		memcpy(value, bytes + data_offset, length);
		value[length] = '\0';
		return 0;
	}

	return INSTALL_ERROR_SFO;
}

static int valid_title_id(const char *title_id)
{
	if (strlen(title_id) != 9)
		return 0;

	for (size_t index = 0; index < 9; index++) {
		char value = title_id[index];

		if (!((value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9')))
			return 0;
	}

	return 1;
}

static void fpkg_hmac(const uint8_t *data, size_t length, uint8_t hmac[16])
{
	uint8_t sha1[SHA1_BLOCK_SIZE];
	uint8_t buffer[64];
	SHA1_CTX context;

	sha1_init(&context);
	sha1_update(&context, data, length);
	sha1_final(&context, sha1);
	memset(buffer, 0, sizeof(buffer));
	memcpy(buffer, sha1 + 4, 8);
	memcpy(buffer + 8, sha1 + 4, 8);
	memcpy(buffer + 16, sha1 + 12, 4);
	buffer[20] = sha1[16];
	buffer[21] = sha1[1];
	buffer[22] = sha1[2];
	buffer[23] = sha1[3];
	memcpy(buffer + 24, buffer + 16, 8);
	sha1_init(&context);
	sha1_update(&context, buffer, sizeof(buffer));
	sha1_final(&context, sha1);
	memcpy(hmac, sha1, 16);
}

static uint32_t read_be32(const uint8_t *data)
{
	uint32_t value;

	memcpy(&value, data, sizeof(value));
	return __builtin_bswap32(value);
}

static int make_head_bin(char *title_id, size_t title_id_size)
{
	void *sfo       = NULL;
	size_t sfo_size = 0;
	int result      = read_file(INSTALL_SFO, &sfo, &sfo_size);

	if (result < 0)
		return result;

	char parsed_title_id[12] = { 0 };
	char content_id[48]      = { 0 };

	result = sfo_string(sfo, sfo_size, "TITLE_ID", parsed_title_id, sizeof(parsed_title_id));
	if (result >= 0 && (!valid_title_id(parsed_title_id) || !strncmp(parsed_title_id, "NPXS", 4)))
		result = INSTALL_ERROR_TITLE_ID;
	if (result >= 0)
		sfo_string(sfo, sfo_size, "CONTENT_ID", content_id, sizeof(content_id));
	if (result >= 0 && content_id[0] &&
	    (strlen(content_id) < 16 || strncmp(content_id + 7, parsed_title_id, 9))) {
		result = INSTALL_ERROR_TITLE_ID;
	}

	free(sfo);
	if (result < 0)
		return result;

	uint8_t *head = malloc(vita_shell_head_bin_len);

	if (head == NULL)
		return INSTALL_ERROR_MEMORY;

	memcpy(head, vita_shell_head_bin, vita_shell_head_bin_len);

	char default_content_id[48] = { 0 };

	snprintf(default_content_id, sizeof(default_content_id), "EP9000-%s_00-0000000000000000",
	         parsed_title_id);

	const char *selected_content_id = content_id[0] ? content_id : default_content_id;

	memset(head + 0x30, 0, 48);

	size_t content_length = bounded_string_length(selected_content_id, 48);

	memcpy(head + 0x30, selected_content_id, content_length);

	uint8_t hmac[16];
	uint32_t length = read_be32(head + 0xD0);

	if ((uint64_t)length + 16 > vita_shell_head_bin_len) {
		free(head);
		return INSTALL_ERROR_SFO;
	}

	fpkg_hmac(head, length, hmac);
	memcpy(head + length, hmac, 16);

	uint32_t offset = read_be32(head + 0x8);

	length = read_be32(head + 0x10);

	uint32_t output = read_be32(head + 0xD4);

	if (length < 64 || (uint64_t)offset + length > vita_shell_head_bin_len ||
	    (uint64_t)output + 16 > vita_shell_head_bin_len) {
		free(head);
		return INSTALL_ERROR_SFO;
	}

	fpkg_hmac(head + offset, length - 64, hmac);
	memcpy(head + output, hmac, 16);

	length = read_be32(head + 0xE8);
	if ((uint64_t)length + 16 > vita_shell_head_bin_len) {
		free(head);
		return INSTALL_ERROR_SFO;
	}

	fpkg_hmac(head, length, hmac);
	memcpy(head + length, hmac, 16);

	result = ensure_parent_directory(INSTALL_HEAD);
	if (result >= 0) {
		SceUID output_file =
		        sceIoOpen(INSTALL_HEAD, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);

		if (output_file < 0) {
			result = output_file;
		} else {
			int written = sceIoWrite(output_file, head, vita_shell_head_bin_len);

			sceIoClose(output_file);
			if (written != (int)vita_shell_head_bin_len)
				result = written < 0 ? written : INSTALL_ERROR_IO;
		}
	}

	free(head);
	if (result < 0)
		return result;

	snprintf(title_id, title_id_size, "%s", parsed_title_id);
	return 0;
}

static struct {
	struct vau_service *service;
	struct vau_content_worker worker;
	struct vau_file_policy policy;
	struct vau_write_journal journal;
	struct vau_write_record record;
	char title[VAU_TITLE_BYTES];
	unsigned initialized, running, installed, promoted;
	uint64_t handle;
} installation;

enum {
	PHASE_IDLE,
	PHASE_EXTRACT,
	PHASE_HEADER,
	PHASE_PROMOTE,
	PHASE_COMPLETE,
	PHASE_FAILED
};

static int install_destination_allowed(const char *path)
{
	return vau_policy_evaluate(&installation.policy, installation.record.request.subject,
	                           VAU_FS_WRITE, path, 1) == VAU_POLICY_ALLOW;
}

static struct vau_write_observation observe_path(const char *path)
{
	struct vau_file_info info = { 0 };
	int rc                    = vau_vita_file_stat(NULL, path, &info);

	if ((uint32_t)rc == 0x80010002u)
		return (struct vau_write_observation){ VAU_STATE_MISSING, 0 };
	if (rc)
		return (struct vau_write_observation){ VAU_STATE_UNKNOWN, 0 };
	return (struct vau_write_observation){ info.kind == VAU_FILE_DIRECTORY ? VAU_STATE_DIRECTORY
		                                   : info.kind == VAU_FILE_REGULAR ? VAU_STATE_FILE
		                                                                   : VAU_STATE_OTHER,
		                                   info.bytes };
}

static int install_execute(void *context, const char *unused_title)
{
	(void)context;
	(void)unused_title;

	int rc = installation_stopped() ? VAU_DENIED : remove_tree(INSTALL_STAGE);

	if (rc >= 0)
		rc = ensure_directory(INSTALL_STAGE);
	if (rc >= 0)
		rc = extract_vpk(installation.record.request.path);
	if (rc >= 0) {
		atomic_store_explicit(&install_phase, PHASE_HEADER, memory_order_relaxed);
		rc = make_head_bin(installation.title, sizeof(installation.title));
	}

	if (rc >= 0) {
		SceIoStat eboot = { 0 };

		rc = sceIoGetstat(INSTALL_STAGE "/eboot.bin", &eboot);
		if (rc >= 0 && (!SCE_S_ISREG(eboot.st_mode) || eboot.st_size <= 0))
			rc = INSTALL_ERROR_ARCHIVE;
	}

	if (rc >= 0) {
		const char *roots[] = { "ux0:app", "ux0:appmeta", "ux0:license/app" };
		char target[VAU_PATH_MAX];

		for (unsigned i = 0; i < 3 && rc >= 0; ++i) {
			snprintf(target, sizeof(target), "%s/%s", roots[i], installation.title);
			if (vau_policy_evaluate(&installation.policy, installation.record.request.subject,
			                        VAU_FS_WRITE, target, 1) != VAU_POLICY_ALLOW) {
				rc = VAU_DENIED;
			}
		}

		snprintf(installation.record.effect_path, sizeof(installation.record.effect_path),
		         "ux0:app/%s", installation.title);
		installation.record.before = observe_path(installation.record.effect_path);
	}

	if (rc >= 0 && installation_stopped())
		rc = VAU_DENIED;
	if (rc >= 0) {
		atomic_store_explicit(&install_phase, PHASE_PROMOTE, memory_order_relaxed);

		/* This same SDK binding is owned by native Content Manager operations.
		 * Busy admission serializes promotion/deletion. Never unload Shell's PAF
		 * or unregister its process-wide PromoterUtil client. */
		rc                    = vau_vita_content_promote(INSTALL_STAGE);
		installation.promoted = rc >= 0;
	}

	int cleaned = remove_tree(INSTALL_STAGE);

	if (rc >= 0 && cleaned < 0)
		rc = cleaned;
	return rc;
}

void vau_vita_install_init(struct vau_service *service)
{
	memset(&installation, 0, sizeof(installation));
	installation.service = service;
	vau_content_worker_init(&installation.worker);
	installation.initialized = 1;
	atomic_init(&install_phase, PHASE_IDLE);
	atomic_init(&install_entries, 0);
	atomic_init(&install_bytes, 0);
}

int vau_vita_install_busy(void)
{
	return installation.initialized && installation.running;
}

void vau_vita_install_poll(void)
{
	if (!installation.running)
		return;

	int result;
	int rc = vau_content_worker_poll(&installation.worker, &result);

	if (rc == VAU_BUSY)
		return;
	if (rc)
		return; /* Keep the slot owned if native thread cleanup fails. */

	installation.record.after = observe_path(installation.record.effect_path);
	if (installation.promoted) {
		/* Native promotion returning success is not the final success marker.
		 * Confirm that Shell's registered installed-app inventory contains it. */
		struct vau_app_entry entry;

		rc = vau_app_registry_find("ur0:shell/db/app.db", installation.title, &entry);
		installation.installed = !rc;
		if (!installation.installed && result >= 0)
			result = rc < 0 ? rc : VAU_DEVICE_ERROR;
	}

	installation.record.phase       = VAU_WRITE_COMPLETE;
	installation.record.result      = result >= 0 ? 0 : result;
	installation.record.offset      = atomic_load_explicit(&install_bytes, memory_order_relaxed);
	installation.record.observed_us = sceKernelGetSystemTimeWide();
	snprintf(installation.record.detail, sizeof(installation.record.detail), "%s",
	         installation.installed ? result < 0 ? "vpk-installed-cleanup-failed" : "vpk-installed"
	                                : "vpk-failed");
	rc = vau_journal_append(&installation.journal, &installation.record);

	int closed = vau_journal_close(&installation.journal);

	if (rc < 0 || closed < 0) {
		installation.installed     = 0;
		installation.record.result = rc < 0 ? rc : closed;
		snprintf(installation.record.detail, sizeof(installation.record.detail), "vpk-audit-error");
	}

	atomic_store_explicit(&install_phase,
	                      installation.installed && result >= 0 ? PHASE_COMPLETE : PHASE_FAILED,
	                      memory_order_relaxed);
	installation.running = 0;
}

static int install_status(const struct vau_write_record *record, int running, char *out,
                          size_t capacity)
{
	static const char *const phases[] = {
		"idle", "extracting", "creating_head", "promoting", "complete", "failed",
	};

	char path[VAU_PATH_MAX * 2 + 3], target[128];

	if (strcmp(record->effect_path, INSTALL_STAGE) && record->effect_path[0] &&
	    (strncmp(record->effect_path, "ux0:app/", 8) ||
	     !vau_title_valid(record->effect_path + 8))) {
		return VAU_DEVICE_ERROR;
	}

	if (vau_json_quote(record->request.path, path, sizeof(path)) < 0 ||
	    vau_json_quote(record->effect_path, target, sizeof(target)) < 0) {
		return VAU_DEVICE_ERROR;
	}

	unsigned phase    = running ? atomic_load_explicit(&install_phase, memory_order_relaxed)
	                    : record->phase != VAU_WRITE_COMPLETE      ? PHASE_IDLE
	                    : !strcmp(record->detail, "vpk-installed") ? PHASE_COMPLETE
	                                                               : PHASE_FAILED;
	const char *title = !strncmp(record->effect_path, "ux0:app/", 8) ? record->effect_path + 8 : "";

	return snprintf(
	        out, capacity,
	        "{\"operation_id\":\"%s\",\"path\":%s,\"state\":\"%s\",\"phase\":\"%s\","
	        "\"running\":%s,\"installed\":%s,\"title_id\":\"%s\",\"target\":%s,\"native_result\":%d,"
	        "\"files_extracted\":%u,\"bytes_extracted\":\"%u\",\"audit_sequence\":\"%llu\"}",
	        record->request.id, path,
	        running                               ? "running"
	        : record->phase != VAU_WRITE_COMPLETE ? "uncertain"
	        : phase == PHASE_COMPLETE             ? "installed"
	                                              : "failed",
	        phases[phase], running ? "true" : "false",
	        running || record->phase != VAU_WRITE_COMPLETE  ? "null"
	        : !strncmp(record->detail, "vpk-installed", 13) ? "true"
	                                                        : "false",
	        title, target, record->result,
	        running ? atomic_load_explicit(&install_entries, memory_order_relaxed) : 0,
	        running ? atomic_load_explicit(&install_bytes, memory_order_relaxed)
	                : (unsigned)record->offset,
	        (unsigned long long)record->sequence);
}

int vau_vita_install(void *context, uint64_t handle, const char *subject, const char *id,
                     const char *path, int start, char *out, size_t capacity)
{
	(void)context;
	if (!installation.initialized || !subject || strlen(subject) != 64 || !id || strlen(id) != 32)
		return VAU_INVALID;

	vau_vita_install_poll();
	if (installation.running) {
		if (strcmp(subject, installation.record.request.subject) ||
		    strcmp(id, installation.record.request.id)) {
			return VAU_BUSY;
		}

		if (start && strcmp(path, installation.record.request.path))
			return VAU_STALE;

		/* Worker mutates only the effect/observations; status uses an immutable
		 * request and never reads worker-owned title/path while it runs. */
		struct vau_write_record view = { 0 };

		view.request  = installation.record.request;
		view.sequence = installation.record.sequence;
		return install_status(&view, 1, out, capacity);
	}

	struct vau_write_journal journal = { 0 };
	int rc = start ? vau_journal_open(&journal, "ur0:data/vita-agent-use/write-audit.db")
	               : vau_journal_open_readonly(&journal, "ur0:data/vita-agent-use/write-audit.db");

	if (rc)
		return rc;

	struct vau_write_record previous;

	rc = vau_journal_state(&journal, subject, id, &previous);
	if (!rc) {
		int closed = vau_journal_close(&journal);

		if (closed)
			return closed;
		if (strncmp(previous.detail, "vpk-", 4) || (start && strcmp(previous.request.path, path)))
			return VAU_STALE;
		return install_status(&previous, 0, out, capacity);
	}

	if (rc != 1 || !start) {
		(void)vau_journal_close(&journal);
		return rc == 1 ? VAU_STALE : rc;
	}

	if (vau_vita_content_busy() || vau_vita_approval_pending(NULL) || installation_stopped()) {
		(void)vau_journal_close(&journal);
		return VAU_BUSY;
	}

	struct vau_file_policy policy;

	rc = vau_vita_acl_load(&policy);

	char normalized[VAU_PATH_MAX], folded[VAU_PATH_MAX];
	size_t length = path ? strlen(path) : 0;

	if (path && length < sizeof(folded))
		for (size_t i = 0; i <= length; i++)
			folded[i] = path[i] >= 'A' && path[i] <= 'Z' ? (char)(path[i] + 32) : path[i];
	else
		folded[0] = 0;
	if (!rc &&
	    (length < 5 || strcmp(path + length - 4, ".vpk") ||
	     vau_path_normalize(path, normalized, sizeof(normalized)) || strcmp(normalized, path) ||
	     !strncmp(folded, INSTALL_STAGE, strlen(INSTALL_STAGE)))) {
		rc = VAU_INVALID;
	}

	if (!rc && (vau_policy_evaluate(&policy, subject, VAU_FS_READ, path, 1) != VAU_POLICY_ALLOW ||
	            vau_policy_evaluate(&policy, subject, VAU_FS_WRITE, INSTALL_STAGE, 1) !=
	                    VAU_POLICY_ALLOW)) {
		rc = VAU_DENIED;
	}

	struct vau_file_info source;

	if (!rc)
		rc = vau_vita_file_stat(NULL, path, &source);
	if (!rc && (source.kind != VAU_FILE_REGULAR || source.bytes < 22 || source.bytes > UINT32_MAX))
		rc = VAU_INVALID;
	if (rc) {
		(void)vau_journal_close(&journal);
		return rc;
	}

	memset(&installation.record, 0, sizeof(installation.record));
	installation.title[0]  = 0;
	installation.installed = installation.promoted = 0;
	installation.policy                            = policy;
	installation.handle                            = handle;
	installation.journal                           = journal;

	struct vau_write_record *record = &installation.record;

	strcpy(record->request.subject, subject);
	strcpy(record->request.id, id);
	strcpy(record->request.path, path);
	record->request.operation = VAU_FS_INSTALL;
	record->request.yes       = 1;
	record->request.bytes     = source.bytes;
	record->phase             = VAU_WRITE_INTENT;
	record->observed_us       = sceKernelGetSystemTimeWide();
	strcpy(record->detail, "vpk-install");
	strcpy(record->effect_path, INSTALL_STAGE);
	record->before = observe_path(INSTALL_STAGE);
	rc             = vau_journal_append(&installation.journal, record);
	if (rc) {
		(void)vau_journal_close(&installation.journal);
		return rc;
	}

	record->effect_started = 1;
	atomic_store_explicit(&install_phase, PHASE_EXTRACT, memory_order_relaxed);
	atomic_store_explicit(&install_entries, 0, memory_order_relaxed);
	atomic_store_explicit(&install_bytes, 0, memory_order_relaxed);
	rc = vau_content_worker_start(&installation.worker, "VPKINST01", install_execute, NULL);
	installation.running = installation.worker.thread >= 0 ||
	                       atomic_load_explicit(&installation.worker.done, memory_order_acquire);
	if (rc && !installation.running) {
		record->phase  = VAU_WRITE_COMPLETE;
		record->result = rc;
		strcpy(record->detail, "vpk-failed");
		(void)vau_journal_append(&installation.journal, record);
		(void)vau_journal_close(&installation.journal);
		return rc;
	}

	struct vau_write_record view = { 0 };

	view.request  = record->request;
	view.sequence = record->sequence;
	return install_status(&view, 1, out, capacity);
}
