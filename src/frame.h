/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_FRAME_H
#define VAU_FRAME_H

#define VAU_FRAME_JPEG_LIMIT (60u * 34u * 1024u + 0x18000u)
#include <stddef.h>
#include "vita_agent.h"

enum vau_frame_stage {
	VAU_FRAME_STAGE_NONE,
	VAU_FRAME_STAGE_POOL,
	VAU_FRAME_STAGE_CAPTURE,
	VAU_FRAME_STAGE_JPEG_INIT,
	VAU_FRAME_STAGE_JPEG_REGION,
	VAU_FRAME_STAGE_JPEG_ENCODE,
	VAU_FRAME_STAGE_CLEANUP,
	VAU_FRAME_STAGE_COUNT
};

enum vau_frame_format {
	VAU_FRAME_FORMAT_NONE,
	VAU_FRAME_FORMAT_JPEG,
	VAU_FRAME_FORMAT_PNG, /* pngshot replaces SceShell's encoder with its PNG writer. */
};

struct vau_frame {
	VauFrameInfo capture;
	const unsigned char *image;
	size_t image_bytes;
	unsigned format;
	unsigned failure_stage; /* No image bytes are published on failure. */
};

/* JPEG: FF D8 ... FF D9. PNG: signature ... IEND chunk. */
unsigned vau_frame_format(const unsigned char *image, size_t bytes);

#endif
