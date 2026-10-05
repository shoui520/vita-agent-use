/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "write_ops.h"
#include "json.h"
#include "format.h"

static int observation(const struct vau_write_observation *s, char *out, size_t capacity)
{
	if (s->state == VAU_STATE_UNKNOWN)
		return vau_snprintf(out, capacity, "{\"known\":false,\"exists\":null}");
	if (s->state == VAU_STATE_MISSING)
		return vau_snprintf(out, capacity, "{\"known\":true,\"exists\":false}");
	return vau_snprintf(out, capacity,
	                    "{\"known\":true,\"exists\":true,\"kind\":\"%s\",\"bytes\":\"%llu\"}",
	                    s->state == VAU_STATE_FILE        ? "file"
	                    : s->state == VAU_STATE_DIRECTORY ? "directory"
	                                                      : "other",
	                    (unsigned long long)s->bytes);
}

int vau_write_changes_json(const struct vau_write_record *r, char *out, size_t capacity)
{
	if (!r || !out)
		return VAU_INVALID;
	if (!r->effect_path[0])
		return vau_snprintf(out, capacity, "[]");

	char path[VAU_PATH_MAX * 2 + 3], target[VAU_PATH_MAX * 2 + 3], before[160], after[160],
	        dbefore[160], dafter[160];
	int moved =
	        r->request.operation == VAU_FS_TRASH || r->request.operation == VAU_FS_RENAME_SOURCE;
	const char *affected = moved ? r->request.path : r->effect_path;

	if (vau_json_quote(affected, path, sizeof(path)) < 0 ||
	    observation(&r->before, before, sizeof(before)) < 0 ||
	    observation(&r->after, after, sizeof(after)) < 0) {
		return VAU_DEVICE_ERROR;
	}

	if (!moved) {
		return vau_snprintf(out, capacity, "[{\"path\":%s,\"before\":%s,\"after\":%s}]", path,
		                    before, after);
	}

	if (vau_json_quote(r->effect_path, target, sizeof(target)) < 0 ||
	    observation(&r->destination_before, dbefore, sizeof(dbefore)) < 0 ||
	    observation(&r->destination_after, dafter, sizeof(dafter)) < 0) {
		return VAU_DEVICE_ERROR;
	}

	return vau_snprintf(
	        out, capacity,
	        "[{\"path\":%s,\"before\":%s,\"after\":%s},{\"path\":%s,\"before\":%s,\"after\":%s}]",
	        path, before, after, target, dbefore, dafter);
}
