/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "frame.h"
#include <string.h>

unsigned vau_frame_format(const unsigned char *image, size_t bytes)
{
	static const unsigned char png[8] = { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };
	/* An IEND chunk is always empty, so its length, type and CRC are fixed. */
	static const unsigned char iend[12] = {
		0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
	};

	if (!image)
		return VAU_FRAME_FORMAT_NONE;
	if (bytes >= 4 && image[0] == 0xff && image[1] == 0xd8 && image[bytes - 2] == 0xff &&
	    image[bytes - 1] == 0xd9) {
		return VAU_FRAME_FORMAT_JPEG;
	}
	if (bytes >= sizeof(png) + sizeof(iend) && !memcmp(image, png, sizeof(png)) &&
	    !memcmp(image + bytes - sizeof(iend), iend, sizeof(iend))) {
		return VAU_FRAME_FORMAT_PNG;
	}

	return VAU_FRAME_FORMAT_NONE;
}
