/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pairing_prompt.h"
#include "vita_agent.h"
#include <string.h>

static void ascii(struct vau_pairing_prompt *p, const char *s)
{
	while (*s)
		p->text[p->length++] = (unsigned char)*s++;
}

int vau_pairing_prompt_text(struct vau_pairing_prompt *out, const char *text, size_t length)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!text || length > 4u * (VAU_PAIRING_TEXT_UNITS - 1u))
		return VAU_INVALID;

	for (size_t i = 0; i < length;) {
		unsigned c = (unsigned char)text[i++], need = 0, min = 0;

		if (c >= 0xc2 && c <= 0xdf) {
			c &= 31;
			need = 1;
			min  = 128;
		} else if (c >= 0xe0 && c <= 0xef) {
			c &= 15;
			need = 2;
			min  = 2048;
		} else if (c >= 0xf0 && c <= 0xf4) {
			c &= 7;
			need = 3;
			min  = 65536;
		} else if (c >= 128 || !c) {
			goto invalid;
		}

		for (unsigned j = 0; j < need; j++) {
			if (i >= length || ((unsigned char)text[i] & 0xc0) != 0x80)
				goto invalid;

			c = (c << 6) | ((unsigned char)text[i++] & 63);
		}

		if (c < min || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
			goto invalid;
		if (out->length + (c >= 65536 ? 2u : 1u) >= VAU_PAIRING_TEXT_UNITS)
			goto invalid;
		if (c >= 65536) {
			c -= 65536;
			out->text[out->length++] = (uint16_t)(0xd800 + (c >> 10));
			c                        = 0xdc00 + (c & 1023);
		}

		out->text[out->length++] = (uint16_t)c;
	}

	return VAU_OK;
invalid:
	memset(out, 0, sizeof(*out));
	return VAU_INVALID;
}

int vau_pairing_prompt_format(struct vau_pairing_prompt *out, const char *name, size_t length,
                              const unsigned char fingerprint[32])
{
	static const char begin[]  = "Pair this computer with your PS Vita?\nAgent name: ";
	static const char middle[] = "\n\nCertificate fingerprint (SHA-256):\n";
	static const char end[]    = "\n\nCompare this fingerprint with the one on your computer.\n"
	                             "Select OK only if they match. Cancel if you did not request this.\n"
	                             "Protected changes still require separate approval.";
	static const char hex[]    = "0123456789ABCDEF";

	_Static_assert(sizeof(begin) - 1 + VAU_AGENT_NAME_BYTES + sizeof(middle) - 1 + 79 +
	                               sizeof(end) <=
	                       VAU_PAIRING_TEXT_UNITS,
	               "Bounded pairing prompt");
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!fingerprint)
		return VAU_INVALID;

	uint16_t label[VAU_AGENT_NAME_BYTES];
	size_t count = 0;
	int rc       = vau_agent_name_utf16(label, &count, name, length);

	if (rc < 0)
		return rc;

	ascii(out, begin);
	memcpy(out->text + out->length, label, count * sizeof(*label));
	out->length += count;
	ascii(out, middle);
	for (unsigned i = 0; i < 32; ++i) {
		if (i && !(i % 2))
			out->text[out->length++] = i == 16 ? '\n' : ' ';
		out->text[out->length++] = hex[fingerprint[i] >> 4];
		out->text[out->length++] = hex[fingerprint[i] & 15];
	}

	ascii(out, end);
	return VAU_OK;
}
