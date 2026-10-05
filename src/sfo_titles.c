/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sfo_titles.h"
#include "json.h"
#include <string.h>

static uint32_t u32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t u16(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

int vau_sfo_titles_read(vau_sfo_read_fn read, void *ctx, uint64_t bytes, struct vau_sfo_titles *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!read || bytes < 20)
		return VAU_INVALID;
	if (bytes > VAU_SFO_METADATA_BYTES)
		return VAU_UNSUPPORTED;

	unsigned char header[20];
	int rc = read(ctx, 0, header, sizeof(header));

	if (rc)
		return rc;
	if (memcmp(header, "\0PSF", 4) || u32(header + 4) != 0x101)
		return VAU_INVALID;

	uint32_t keys = u32(header + 8), data = u32(header + 12), count = u32(header + 16);

	if (keys < 20 || keys > data || data > bytes || count > (keys - 20) / 16 || keys % 4 ||
	    data % 4) {
		return VAU_INVALID;
	}

	struct vau_sfo_titles result = { 0 };
	unsigned found               = 0;
	unsigned char indexes[256];

	for (uint32_t i = 0; i < count; i++) {
		if (!(i % 16)) {
			uint32_t entries = count - i;

			if (entries > 16)
				entries = 16;
			rc = read(ctx, 20 + (uint64_t)i * 16, indexes, entries * 16);
			if (rc)
				return rc;
		}

		const unsigned char *entry = indexes + (i % 16) * 16;
		uint32_t key = u16(entry), length = u32(entry + 4), capacity = u32(entry + 8),
		         offset = u32(entry + 12);

		if (key >= data - keys || length > capacity || offset > bytes - data ||
		    capacity > bytes - data - offset) {
			return VAU_INVALID;
		}

		char name[32];
		uint32_t n = data - keys - key;

		if (n > sizeof(name))
			n = sizeof(name);
		rc = read(ctx, (uint64_t)keys + key, name, n);
		if (rc)
			return rc;
		if (!memchr(name, 0, n))
			return VAU_INVALID;

		unsigned bit = !strcmp(name, "TITLE") ? 1 : !strcmp(name, "SAVEDATA_TITLE") ? 2 : 0;

		if (!bit)
			continue;
		if (found & bit || u16(entry + 2) != 0x204 || !length)
			return VAU_INVALID;
		if (length > VAU_SFO_TITLE_BYTES)
			return VAU_UNSUPPORTED;

		char *title = bit == 1 ? result.title : result.savedata_title;

		rc = read(ctx, (uint64_t)data + offset, title, length);
		if (rc)
			return rc;

		char *end = memchr(title, 0, length);

		if (!end)
			return VAU_INVALID;

		for (char *p = end; p < title + length; p++)
			if (*p)
				return VAU_INVALID;

		char quoted[VAU_SFO_TITLE_BYTES * 6 + 3];

		if (vau_json_quote(title, quoted, sizeof(quoted)) < 0)
			return VAU_INVALID;

		found |= bit;
	}

	*out = result;
	return VAU_OK;
}

struct pbp_region {
	vau_sfo_read_fn read;
	void *context;
	uint64_t offset, bytes;
};

static int read_region(void *context, uint64_t offset, void *data, uint32_t count)
{
	struct pbp_region *r = context;

	if (offset > r->bytes || count > r->bytes - offset)
		return VAU_INVALID;
	return r->read(r->context, r->offset + offset, data, count);
}

int vau_pbp_titles_read(vau_sfo_read_fn read, void *context, uint64_t bytes,
                        struct vau_sfo_titles *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!read || bytes < 40)
		return VAU_INVALID;

	unsigned char header[40];
	int rc = read(context, 0, header, sizeof(header));

	if (rc)
		return rc;
	if (memcmp(header, "\0PBP", 4))
		return VAU_INVALID;

	uint32_t start = u32(header + 8), end = u32(header + 12);

	if (start < sizeof(header) || end < start || end > bytes)
		return VAU_INVALID;

	/* Only the SFO region is interpreted. The executable/audio/image offsets
	 * are irrelevant to this read-only metadata query, as is the version word. */
	struct pbp_region region = { read, context, start, (uint64_t)end - start };

	return vau_sfo_titles_read(read_region, &region, region.bytes, out);
}
