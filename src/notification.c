/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "notification.h"
#include "vita_agent.h"
#include <string.h>

_Static_assert(sizeof(struct vau_notification) == 0x470, "3.65 notification ABI");
_Static_assert(offsetof(struct vau_notification, activation_uri) == 0x80, "URI offset");
_Static_assert(offsetof(struct vau_notification, reserved) == 0x468, "reserved offset");

int vau_agent_name_utf16(uint16_t units[VAU_AGENT_NAME_BYTES], size_t *out_count, const char *name,
                         size_t length)
{
	size_t count = 0;

	if (!units || !out_count)
		return VAU_INVALID;

	*out_count = 0;
	if (!name || !length || length > VAU_AGENT_NAME_BYTES)
		return VAU_INVALID;

	for (size_t i = 0; i < length;) {
		uint32_t c = (unsigned char)name[i++], minimum = 0;
		unsigned continuation = 0;

		if (c >= 0xc2 && c <= 0xdf) {
			c &= 31;
			continuation = 1;
			minimum      = 0x80;
		} else if (c >= 0xe0 && c <= 0xef) {
			c &= 15;
			continuation = 2;
			minimum      = 0x800;
		} else if (c >= 0xf0 && c <= 0xf4) {
			c &= 7;
			continuation = 3;
			minimum      = 0x10000;
		} else if (c >= 128) {
			return VAU_INVALID;
		}

		if (length - i < continuation)
			return VAU_INVALID;

		while (continuation--) {
			unsigned next = (unsigned char)name[i++];

			if ((next & 0xc0) != 0x80)
				return VAU_INVALID;

			c = (c << 6) | (next & 63);
		}

		if (c < minimum || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff) || c < 32 ||
		    (c >= 0x7f && c <= 0x9f) || (c >= 0x2028 && c <= 0x202e) ||
		    (c >= 0x2066 && c <= 0x2069)) {
			return VAU_INVALID;
		}

		if (c > 0xffff) {
			c -= 0x10000;
			units[count++] = (uint16_t)(0xd800 + (c >> 10));
			units[count++] = (uint16_t)(0xdc00 + (c & 1023));
		} else {
			units[count++] = (uint16_t)c;
		}
	}

	*out_count = count;
	return VAU_OK;
}

int vau_notification_using(struct vau_notification *out, const char *name, size_t length)
{
	static const char suffix[] = " is using your PS Vita. PS+SELECT to stop.";
	uint16_t units[VAU_AGENT_NAME_BYTES];
	size_t count = 0;

	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	int rc = vau_agent_name_utf16(units, &count, name, length);

	if (rc < 0)
		return rc;

	size_t available = 63 - (sizeof(suffix) - 1), keep = count;

	if (keep > available) {
		keep = available - 1;
		if (units[keep - 1] >= 0xd800 && units[keep - 1] <= 0xdbff)
			--keep;
	}

	memcpy(out->text, units, keep * sizeof(*units));
	if (keep < count)
		out->text[keep++] = 0x2026;
	for (size_t i = 0; i < sizeof(suffix) - 1; ++i)
		out->text[keep++] = (uint16_t)suffix[i];
	return VAU_OK;
}

_Static_assert(sizeof(struct vau_styled_notification) == 0x4e8, "3.65 ProgressFinish ABI");
_Static_assert(offsetof(struct vau_styled_notification, subtitle) == 0x80,
               "Native subtitle offset");
_Static_assert(offsetof(struct vau_styled_notification, activation_uri) == 0x100,
               "Native finish URI offset");

int vau_notification_using_styled(struct vau_styled_notification *out, const char *name,
                                  size_t length)
{
	static const char suffix[]   = " is using your PS Vita.";
	static const char subtitle[] = "PS+SELECT to stop.";
	uint16_t units[VAU_AGENT_NAME_BYTES];
	size_t count = 0;

	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	int rc = vau_agent_name_utf16(units, &count, name, length);

	if (rc < 0)
		return rc;

	size_t available = 63 - (sizeof(suffix) - 1), keep = count;

	if (keep > available) {
		keep = available - 1;
		if (units[keep - 1] >= 0xd800 && units[keep - 1] <= 0xdbff)
			--keep;
	}

	memcpy(out->title, units, keep * sizeof(*units));
	if (keep < count)
		out->title[keep++] = 0x2026;
	for (size_t i = 0; i < sizeof(suffix) - 1; i++)
		out->title[keep++] = (uint16_t)suffix[i];
	for (size_t i = 0; i < sizeof(subtitle) - 1; i++)
		out->subtitle[i] = (uint16_t)subtitle[i];
	return VAU_OK;
}
