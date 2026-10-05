/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "module_variable.h"
#include "native_ops.h"

static uint16_t u16(const unsigned char *p)
{
	return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t u32(const unsigned char *p)
{
	return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int vau_module_variable(void *context, vau_memory_read read, uintptr_t start, uintptr_t end,
                        uint32_t library, uint32_t nid, uintptr_t *out)
{
	if (!out)
		return VAU_INVALID;

	*out = 0;
	if (!read || !start || start >= end || (start & 3) || (end & 3) || end > UINT32_MAX ||
	    end - start > 65536) {
		return VAU_INVALID;
	}

	uintptr_t found = 0;

	while (start < end) {
		unsigned char h[32];

		if (end - start < sizeof(h))
			return VAU_DEVICE_ERROR;

		int rc = read(context, start, h, sizeof(h));

		if (rc)
			return rc;

		unsigned size = u16(h), functions = u16(h + 6), variables = u16(h + 8);

		if (size < 32 || (size & 3) || size > end - start)
			return VAU_DEVICE_ERROR;
		if (u32(h + 16) == library) {
			uint32_t nids = u32(h + 24), entries = u32(h + 28);
			uint64_t bytes = ((uint64_t)functions + variables) * 4;

			if (variables && (!nids || !entries || (nids & 3) || (entries & 3) ||
			                  bytes > UINT32_MAX - nids || bytes > UINT32_MAX - entries)) {
				return VAU_DEVICE_ERROR;
			}

			for (unsigned i = 0; i < variables; i++) {
				unsigned char value[4];
				uintptr_t offset = ((uintptr_t)functions + i) * 4;

				rc = read(context, nids + offset, value, sizeof(value));
				if (rc)
					return rc;
				if (u32(value) == nid) {
					rc = read(context, entries + offset, value, sizeof(value));
					if (rc)
						return rc;

					uintptr_t address = u32(value);

					if (!address || (address & 3) || found)
						return VAU_DEVICE_ERROR;

					found = address;
				}
			}
		}

		start += size;
	}

	if (!found)
		return VAU_UNSUPPORTED;

	*out = found;
	return 0;
}
