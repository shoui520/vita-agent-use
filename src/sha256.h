/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_SHA256_H
#define VAU_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* Allocation-free digest for canonical command replay identity. */
struct vau_sha256 {
	uint32_t state[8];
	uint64_t bytes;
	unsigned used;
	unsigned char block[64];
};

void vau_sha256_init(struct vau_sha256 *);
void vau_sha256_update(struct vau_sha256 *, const void *, size_t);
void vau_sha256_finish(struct vau_sha256 *, unsigned char[32]);

#endif
