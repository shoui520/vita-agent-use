/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sqlite_json.h"
#include "json.h"
#include "vita_agent.h"
#include "format.h"
#include <string.h>

static int last_index = -1, last_type, last_bytes;
static size_t last_cap;
static const char *last_reason = "not_recorded";

void vau_sqlite_json_reset(void)
{
	last_index = -1;
	last_type = last_bytes = 0;
	last_cap               = 0;
	last_reason            = "not_recorded";
}

int vau_vita_metadata_error(void *ctx, char *out, size_t cap)
{
	(void)ctx;
	if (last_index < 0)
		return 0;
	return vau_snprintf(
	        out, cap,
	        "{\"column_index\":%d,\"sqlite_type\":%d,\"column_bytes\":%d,\"available_response_bytes\":%u,\"reason\":\"%s\"}",
	        last_index, last_type, last_bytes, (unsigned)last_cap, last_reason);
}

static int binary(const void *data, size_t bytes, const char *type, char *out, size_t cap)
{
	if (!strcmp(type, "blob") && bytes > 1024) {
		int n = vau_snprintf(
		        out, cap, "{\"storage_type\":\"blob\",\"bytes\":\"%llu\",\"data_included\":false}",
		        (unsigned long long)bytes);

		return n < 0 || (size_t)n >= cap ? VAU_UNSUPPORTED : n;
	}

	if (bytes > 1024 || (!data && bytes))
		return VAU_UNSUPPORTED;

	int n = vau_snprintf(out, cap, "{\"encoding\":\"hex\",\"storage_type\":\"%s\",\"data\":\"",
	                     type);

	if (n < 0 || (size_t)n + bytes * 2 + 3 > cap)
		return VAU_UNSUPPORTED;

	const unsigned char *p     = data;
	static const char digits[] = "0123456789abcdef";

	for (size_t i = 0; i < bytes; i++) {
		out[n++] = digits[p[i] >> 4];
		out[n++] = digits[p[i] & 15];
	}

	out[n++] = '"';
	out[n++] = '}';
	out[n]   = 0;
	return n;
}

int vau_sqlite_json_column(sqlite3_stmt *s, int index, char *out, size_t cap, int string)
{
	int type = sqlite3_column_type(s, index);

	last_index  = index;
	last_type   = type;
	last_bytes  = sqlite3_column_bytes(s, index);
	last_cap    = cap;
	last_reason = last_bytes > 1024 ? "field_bytes_limit" : "response_capacity_or_encoding";
	if (type == 5) {
		if (cap < 5)
			return VAU_UNSUPPORTED;

		memcpy(out, "null", 5);
		return 4;
	}

	if (type == 4) {
		const void *data = sqlite3_column_blob(s, index);
		int bytes        = sqlite3_column_bytes(s, index);

		return bytes < 0 ? VAU_DEVICE_ERROR : binary(data, (size_t)bytes, "blob", out, cap);
	}

	const unsigned char *text = sqlite3_column_text(s, index);
	int bytes                 = sqlite3_column_bytes(s, index);

	if (!text || bytes < 0 || bytes > 1024)
		return VAU_UNSUPPORTED;
	if (memchr(text, 0, (size_t)bytes))
		return binary(text, (size_t)bytes, "text", out, cap);
	if (!string && (type == 1 || type == 2)) {
		struct vau_json_token token[2];
		size_t count;

		if (vau_json_parse((const char *)text, (size_t)bytes, token, 2, &count) || count != 1 ||
		    token[0].type != VAU_JSON_NUMBER) {
			return VAU_DEVICE_ERROR;
		}

		if ((size_t)bytes + 1 > cap)
			return VAU_UNSUPPORTED;

		memcpy(out, text, (size_t)bytes);
		out[bytes] = 0;
		return bytes;
	}

	int n = vau_json_quote((const char *)text, out, cap);

	return n < 0 ? binary(text, (size_t)bytes, "text", out, cap) : n;
}
