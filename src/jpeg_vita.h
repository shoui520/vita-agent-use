/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_JPEG_VITA_H
#define VAU_JPEG_VITA_H

#include <stddef.h>
#include <stdint.h>
#include "vita_agent.h"

struct vau_jpeg_encoder {
	uint32_t context[96]; /* 3.65 native context size: 0x180. */
	void *yuv, *output;
	size_t yuv_bytes, output_capacity;
	unsigned width, height;
	int ready;
};

/* Single user worker. Initialize struct to zero. Owner supplies separate,
 * 256-byte-aligned physically contiguous LPDDR2 YUV/output buffers; capacity
 * and lifetime must cover all calls. No files or Photos database are touched.
 * Width/height must be multiples of 16, 64..960 and 64..544 respectively.
 * Native ratio is 0..255, NOT a libjpeg quality percentage (default is 64).
 * ARGB snapshots must remain stable until encode returns. */
int vau_jpeg_init(struct vau_jpeg_encoder *e, unsigned width, unsigned height, void *yuv,
                  size_t yuv_bytes, void *output, size_t output_capacity, unsigned ratio);
int vau_jpeg_encode(struct vau_jpeg_encoder *e, const void *argb, size_t argb_bytes,
                    unsigned pitch_pixels, size_t *jpeg_bytes);
int vau_jpeg_end(struct vau_jpeg_encoder *e);
int vau_jpeg_region(struct vau_jpeg_encoder *e, unsigned width, unsigned height);

#endif
