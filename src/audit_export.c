/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "audit_export.h"
#include "json.h"
#include "format.h"
#include <string.h>
#include <stdarg.h>

struct output {
	char *data;
	size_t capacity, used;
	int error;
};

static void add(struct output *o, const char *format, ...)
{
	if (o->error)
		return;

	va_list args;

	va_start(args, format);

	int n = vau_vsnprintf(o->data + o->used, o->capacity - o->used, format, args);

	va_end(args);
	if (n < 0 || (size_t)n >= o->capacity - o->used)
		o->error = VAU_INVALID;
	else
		o->used += (size_t)n;
}

static void field(struct output *o, const char *key, const char *value)
{
	char quoted[VAU_PATH_MAX * 6 + 3];

	if (vau_json_quote(value, quoted, sizeof(quoted)) < 0) {
		o->error = VAU_DEVICE_ERROR;
		return;
	}

	add(o, "\"%s\":%s,", key, quoted);
}

int vau_audit_export(struct vau_write_journal *j, uint64_t after, char *data, size_t capacity)
{
	if (!data || capacity < VAU_AUDIT_EXPORT_BYTES)
		return VAU_INVALID;

	struct vau_audit_page page;
	int rc = vau_journal_page(j, after, 0, &page);

	if (rc)
		return rc;

	struct output o = { data, capacity, 0, 0 };

	add(&o, "{\"v\":1,\"after\":\"%llu\",\"next_sequence\":\"%llu\",\"more\":%s,\"events\":[",
	    (unsigned long long)after, (unsigned long long)page.next_sequence,
	    page.more ? "true" : "false");
	for (unsigned i = 0; i < page.count; ++i) {
		const struct vau_write_record *r  = &page.records[i];
		const struct vau_write_request *q = &r->request;

		add(&o, "%s{\"sequence\":\"%llu\",", i ? "," : "", (unsigned long long)r->sequence);
		field(&o, "subject", q->subject);
		field(&o, "operation_id", q->id);
		field(&o, "path", q->path);
		field(&o, "destination", q->destination);
		field(&o, "sha256", q->sha256);
		field(&o, "expected_sha256", q->expected_sha256);
		field(&o, "detail", r->detail);
		field(&o, "trash_id", q->trash_id);
		field(&o, "detail_path", r->detail_path);
		field(&o, "effect_path", r->effect_path);

		char changes[4096];
		int changed = vau_write_changes_json(r, changes, sizeof(changes));

		if (changed < 0 || changed >= (int)sizeof(changes)) {
			o.error = VAU_DEVICE_ERROR;
			break;
		}

		add(&o, "\"changes\":%s,", changes);
		add(&o,
		    "\"phase\":%u,\"operation\":%u,\"yes\":%s,\"recursive\":%s,\"overwrite\":%s,"
		    "\"bytes\":\"%llu\",\"result\":%d,\"effect_started\":%s,\"readback_required\":%s,"
		    "\"observed_us\":\"%llu\",\"offset\":\"%llu\"}",
		    r->phase, q->operation, q->yes ? "true" : "false", q->recursive ? "true" : "false",
		    q->overwrite ? "true" : "false", (unsigned long long)q->bytes, r->result,
		    r->effect_started ? "true" : "false", r->readback_required ? "true" : "false",
		    (unsigned long long)r->observed_us, (unsigned long long)r->offset);
	}

	add(&o, "]}");
	return o.error ? o.error : (int)o.used;
}
