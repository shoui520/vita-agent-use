/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "upload_wire.h"
#include "json.h"
#include "protocol.h"

_Static_assert(4u + VAU_UPLOAD_METADATA_BYTES + VAU_UPLOAD_CHUNK_BYTES <= VAU_REQUEST_BYTES,
               "Upload envelope must fit the existing HTTP body buffer");

#include "format.h"
#include <string.h>

static int hex(const char *s, size_t length)
{
	if (strlen(s) != length)
		return 0;

	for (size_t i = 0; i < length; ++i)
		if (!strchr("0123456789abcdef", s[i]))
			return 0;
	return 1;
}

static int integer(const char *json, const struct vau_json_token *token, uint64_t *out)
{
	char s[21];

	if (vau_json_ascii(json, token, s, sizeof(s)) || !s[0] || (s[0] == '0' && s[1]))
		return VAU_INVALID;

	struct vau_json_token number = { 0, strlen(s), 0, VAU_JSON_NUMBER };

	return vau_json_u64(s, &number, out) || *out > INT64_MAX ? VAU_INVALID : VAU_OK;
}

/*
 * POST /v1/file/upload body:
 *
 *   [u32 big-endian n][n bytes of JSON metadata][chunk bytes, the rest]
 *
 * The JSON names the action (begin, chunk, verify, commit, recover) and the
 * request; subject is the authenticated peer's identity, never read from the body.
 */
int vau_upload_wire_parse(const void *body, size_t bytes, const char *subject,
                          struct vau_upload_message *out)
{
	if (!body || !subject || !out || bytes < 4 || !hex(subject, 64))
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	const unsigned char *p = body;
	uint32_t length =
	        ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];

	if (!length || length > VAU_UPLOAD_METADATA_BYTES || length > bytes - 4 ||
	    bytes - 4 - length > VAU_UPLOAD_CHUNK_BYTES) {
		return VAU_INVALID;
	}

	const char *json = (const char *)p + 4;
	struct vau_json_token t[32];
	size_t count;

	if (vau_json_parse(json, length, t, 32, &count) || t[0].type != VAU_JSON_OBJECT)
		return VAU_INVALID;

	unsigned seen               = 0;
	struct vau_write_request *r = &out->request;

	r->operation = VAU_FS_WRITE;
	strcpy(r->subject, subject);
	static const char *const actions[] = { "begin", "chunk", "verify", "commit", "recover" };
	for (size_t i = 1; i < t[0].next; i = t[i + 1].next) {
		char key[24];
		unsigned bit;

		if (vau_json_ascii(json, &t[i], key, sizeof(key)))
			return VAU_INVALID;
		if (!strcmp(key, "action")) {
			char action[16];

			bit = 1;
			if (vau_json_ascii(json, &t[i + 1], action, sizeof(action)))
				return VAU_INVALID;

			unsigned j;

			for (j = 0; j < 5; ++j)
				if (!strcmp(action, actions[j]))
					break;
			if (j == 5)
				return VAU_INVALID;

			out->action = (enum vau_upload_action)j;
		} else if (!strcmp(key, "operation_id")) {
			bit = 2;
			if (vau_json_ascii(json, &t[i + 1], r->id, sizeof(r->id)) || !hex(r->id, 32))
				return VAU_INVALID;
		} else if (!strcmp(key, "path")) {
			char path[VAU_PATH_MAX];

			bit = 4;
			if (vau_json_utf8(json, &t[i + 1], path, sizeof(path)) ||
			    vau_path_normalize(path, r->path, sizeof(r->path))) {
				return VAU_INVALID;
			}
		} else if (!strcmp(key, "bytes") || !strcmp(key, "offset")) {
			bit = !strcmp(key, "bytes") ? 8 : 16;
			if (integer(json, &t[i + 1], bit == 8 ? &r->bytes : &out->offset))
				return VAU_INVALID;
		} else if (!strcmp(key, "sha256") || !strcmp(key, "expected_sha256")) {
			bit = !strcmp(key, "sha256") ? 32 : 64;
			if (vau_json_ascii(json, &t[i + 1], bit == 32 ? r->sha256 : r->expected_sha256, 65))
				return VAU_INVALID;
		} else if (!strcmp(key, "overwrite") || !strcmp(key, "yes")) {
			bit = !strcmp(key, "overwrite") ? 128 : 256;
			if (t[i + 1].type != VAU_JSON_TRUE && t[i + 1].type != VAU_JSON_FALSE)
				return VAU_INVALID;
			if (bit == 128)
				r->overwrite = t[i + 1].type == VAU_JSON_TRUE;
			else
				r->yes = t[i + 1].type == VAU_JSON_TRUE;
		} else {
			return VAU_INVALID;
		}

		if (seen & bit)
			return VAU_INVALID;

		seen |= bit;
	}

	if (seen != 511 || !hex(r->sha256, 64) ||
	    (r->overwrite ? (*r->expected_sha256 && !hex(r->expected_sha256, 64))
	                  : !!r->expected_sha256[0])) {
		return VAU_INVALID;
	}

	out->data       = p + 4 + length;
	out->data_bytes = (uint32_t)(bytes - 4 - length);
	if (out->action == VAU_UPLOAD_CHUNK) {
		if (!out->data_bytes || out->offset > r->bytes || out->data_bytes > r->bytes - out->offset)
			return VAU_INVALID;
	} else if (out->data_bytes || out->offset) {
		return VAU_INVALID;
	}

	return VAU_OK;
}

int vau_upload_wire_reply(const struct vau_upload_message *m, int rc,
                          const struct vau_upload_status *status,
                          const struct vau_write_record *record, char *output, size_t capacity)
{
	int complete = record->sequence && record->phase == VAU_WRITE_COMPLETE;

	return vau_snprintf(
	        output, capacity,
	        "{\"v\":1,\"operation_id\":\"%s\",\"action\":%u,\"code\":%d,"
	        "\"received\":\"%llu\",\"verified\":%s,\"complete\":%s,\"sequence\":\"%llu\","
	        "\"effect_started\":%s,\"readback_required\":%s}",
	        m->request.id, m->action, rc, (unsigned long long)status->received,
	        status->verified ? "true" : "false", complete ? "true" : "false",
	        (unsigned long long)record->sequence, record->effect_started ? "true" : "false",
	        record->readback_required ? "true" : "false");
}
