/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_LOG_MARKER_H
#define VAU_LOG_MARKER_H

#include <stddef.h>
#include <stdint.h>

#define VAU_LOG_MARKER_BYTES 128u

struct vau_log_marker {
	unsigned char text[VAU_LOG_MARKER_BYTES];
	uint8_t prefix[VAU_LOG_MARKER_BYTES];
	uint32_t length, matched;
	uint64_t offset, hits;
};

int vau_log_marker_init(struct vau_log_marker *, const void *, size_t, uint64_t);

/* Emits stream offsets immediately after each marker, even across read chunks.
 * Counts every match, but bounds caller output without stopping stream analysis. */
size_t vau_log_marker_feed(struct vau_log_marker *, const void *, size_t, uint64_t *, size_t);

#endif
