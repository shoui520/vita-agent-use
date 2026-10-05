/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_scope.h"
#include "format.h"
#include "json.h"
#include <string.h>

static int same(const struct vau_content_delete_request *a,
                const struct vau_content_delete_request *b)
{
	return vau_content_delete_target_same(a, b);
}

static int done(sqlite3_stmt *s, int rc)
{
	if (s) {
		int end = sqlite3_finalize(s);

		if (!rc && end)
			rc = -65536 - end;
	}

	return rc;
}

int vau_content_changes_json(struct vau_content_journal *j,
                             const struct vau_content_delete_request *request, uint64_t before,
                             uint64_t after, uint64_t cursor, char *out, size_t cap)
{
	if (!out || !cap)
		return VAU_INVALID;

	out[0] = 0;
	if (!j || !j->db || !vau_content_delete_request_valid(request) || !before ||
	    before > INT64_MAX || after > INT64_MAX || cursor > INT64_MAX) {
		return VAU_INVALID;
	}

	struct vau_content_scope left, right;
	int rc = vau_content_scope_get(j, before, &left);

	if (rc)
		return rc == 1 ? VAU_STALE : rc;
	if (!same(request, &left.request) || left.phase == VAU_CONTENT_SCOPE_AFTER)
		return VAU_STALE;
	if (after) {
		rc = vau_content_scope_get(j, after, &right);
		if (rc)
			return rc == 1 ? VAU_STALE : rc;
		if (!same(request, &right.request) || right.phase != VAU_CONTENT_SCOPE_AFTER ||
		    after <= before) {
			return VAU_STALE;
		}
	}

	/* Emit before rows plus after-only rows, using immutable row sequences as
	 * cursor. A new after path has no invented before observation. */
	sqlite3_stmt *s = NULL;

	rc = sqlite3_prepare_v2(
	        j->db,
	        "SELECT sequence,path,0 FROM content_scope_paths WHERE "
	        "scope_sequence=CAST(?1 AS INTEGER) AND sequence>CAST(?3 AS INTEGER) UNION ALL "
	        "SELECT sequence,path,1 FROM content_scope_paths a WHERE scope_sequence=CAST(?2 AS INTEGER) "
	        "AND sequence>CAST(?3 AS INTEGER) AND NOT EXISTS(SELECT 1 FROM content_scope_paths b "
	        "WHERE b.scope_sequence=CAST(?1 AS INTEGER) AND b.path=a.path) ORDER BY sequence LIMIT 2",
	        -1, &s, NULL);

	char values[3][24];

	uint64_t numbers[] = { before, after, cursor };

	for (unsigned i = 0; i < 3 && !rc; i++) {
		vau_snprintf(values[i], sizeof(values[i]), "%llu", (unsigned long long)numbers[i]);
		rc = sqlite3_bind_text(s, i + 1, values[i], -1, NULL);
	}

	int present = 0, more = 0, side = 0;
	uint64_t next = cursor;
	char path[VAU_PATH_MAX];

	if (!rc) {
		int step = sqlite3_step(s);

		if (step == 100) {
			const unsigned char *p = sqlite3_column_text(s, 1), *seq = sqlite3_column_text(s, 0);
			int bytes = sqlite3_column_bytes(s, 1), n = sqlite3_column_bytes(s, 0);

			if (!p || bytes <= 0 || (size_t)bytes >= sizeof(path) || memchr(p, 0, (size_t)bytes) ||
			    !seq || n <= 0) {
				rc = VAU_DEVICE_ERROR;
			} else {
				next = 0;
				for (int i = 0; i < n; i++) {
					if (seq[i] < '0' || seq[i] > '9' ||
					    next > ((uint64_t)INT64_MAX - (unsigned)(seq[i] - '0')) / 10) {
						rc = VAU_DEVICE_ERROR;
						break;
					}

					next = next * 10 + (unsigned)(seq[i] - '0');
				}

				if (!rc && next <= cursor)
					rc = VAU_STALE;
				memcpy(path, p, (size_t)bytes);
				path[bytes] = 0;

				const unsigned char *flag = sqlite3_column_text(s, 2);

				if (!flag || sqlite3_column_bytes(s, 2) != 1 || (*flag != '0' && *flag != '1'))
					rc = VAU_DEVICE_ERROR;
				else
					side = *flag - '0';
				present = 1;
			}

			if (!rc) {
				step = sqlite3_step(s);
				if (step == 100)
					more = 1;
				else if (step != 101)
					rc = -65536 - step;
			}
		} else if (step != 101) {
			rc = -65536 - step;
		}
	} else {
		rc = -65536 - rc;
	}

	rc = done(s, rc);
	if (rc)
		return rc;

	char change[2400] = "";

	if (present) {
		struct vau_content_scope_path b, a;
		const struct vau_content_scope_path *bp = NULL, *ap = NULL;

		rc = vau_content_scope_find(j, side ? after : before, path, side ? &a : &b);
		if (rc)
			return rc == 1 ? VAU_STALE : rc;
		if (side)
			ap = &a;
		else
			bp = &b;
		if (after && !side) {
			rc = vau_content_scope_find(j, after, path, &a);
			if (!rc)
				ap = &a;
			else if (rc != 1)
				return rc;
		}

		int n = vau_content_scope_changes_json(bp, ap, change, sizeof(change));

		if (n < 0)
			return n;
	}

	char target[64];
	int rc_target = vau_content_target_json(request, target, sizeof(target));

	if (rc_target < 0)
		return rc_target;

	int n = vau_snprintf(
	        out, cap,
	        "{\"operation_id\":\"%s\"%s,\"before_scope\":\"%llu\",\"after_scope\":\"%llu\","
	        "\"before_phase\":\"%s\",\"changes\":[%s],\"next_cursor\":\"%llu\",\"more\":%s}",
	        request->id, target, (unsigned long long)before, (unsigned long long)after,
	        left.phase == VAU_CONTENT_SCOPE_PREVIEW ? "preview" : "before", change,
	        (unsigned long long)next, more ? "true" : "false");

	if (n < 0 || (size_t)n >= cap) {
		out[0] = 0;
		return VAU_UNSUPPORTED;
	}

	return n;
}

int vau_content_audit_json(struct vau_content_journal *j, uint64_t cursor, char *out, size_t cap)
{
	if (!out || !cap)
		return VAU_INVALID;

	out[0] = 0;

	struct vau_content_audit_page page;
	int rc = vau_content_journal_page(j, cursor, &page);

	if (rc)
		return rc;

	char entries[2][896] = { { 0 } };

	for (unsigned i = 0; i < page.count; i++) {
		char record[768];
		int n = vau_content_record_json(&page.events[i].record, 1, record, sizeof(record));

		if (n < 0)
			return n;

		n = vau_snprintf(entries[i], sizeof(entries[i]), "{\"sequence\":\"%llu\",\"record\":%s}",
		                 (unsigned long long)page.events[i].sequence, record);
		if (n < 0 || (size_t)n >= sizeof(entries[i]))
			return VAU_UNSUPPORTED;
	}

	int n = vau_snprintf(out, cap, "{\"events\":[%s%s%s],\"next_cursor\":\"%llu\",\"more\":%s}",
	                     entries[0], page.count > 1 ? "," : "", entries[1],
	                     (unsigned long long)page.next, page.more ? "true" : "false");

	if (n < 0 || (size_t)n >= cap) {
		out[0] = 0;
		return VAU_UNSUPPORTED;
	}

	return n;
}

/* Append directly into the transport buffer: a 1023-byte source path may
 * expand sixfold in JSON. No path-sized escaping scratch or truncation. */
static int media_metadata(struct vau_content_journal *j, uint64_t scope, char *out, size_t cap)
{
	struct vau_content_media_observation source;
	struct vau_content_album_page album_page;
	int rc = vau_content_scope_media_get(j, scope, &source);

	if (rc)
		return rc;

	int observed = vau_content_scope_albums_page(j, scope, INT64_MAX, INT64_MAX, &album_page);

	if (observed)
		return observed;

	const struct vau_content_album_set albums = album_page.set;
	size_t used                               = 0;
	int n;

	if (source.state == VAU_MEDIA_PRESENT) {
		const struct vau_content_media_record *r = &source.record;
		char bytes[32]                           = "null";

		if (r->bytes_known)
			vau_snprintf(bytes, sizeof(bytes), "\"%llu\"", (unsigned long long)r->bytes);
		n = vau_snprintf(
		        out, cap,
		        ",\"source_observation\":{\"known\":true,\"exists\":true,"
		        "\"category\":%u,\"media_id\":\"%llu\",\"status\":%u,\"bytes\":%s,\"path\":",
		        r->category, (unsigned long long)r->id, r->status, bytes);
		if (n < 0 || (size_t)n >= cap)
			return VAU_UNSUPPORTED;

		used = (size_t)n;
		n    = vau_json_quote(r->path, out + used, cap - used);
		if (n < 0)
			return VAU_UNSUPPORTED;

		used += (size_t)n;
		n = vau_snprintf(out + used, cap - used, "}");
	} else if (source.state == VAU_MEDIA_ABSENT) {
		n = vau_snprintf(out, cap, ",\"source_observation\":{\"known\":true,\"exists\":false}");
	} else {
		n = vau_snprintf(
		        out, cap,
		        ",\"source_observation\":{\"known\":false,\"exists\":null,\"native_error\":%d}",
		        source.error);
	}

	if (n < 0 || (size_t)n >= cap - used)
		return VAU_UNSUPPORTED;

	used += (size_t)n;
	if (!album_page.known) {
		n = vau_snprintf(out + used, cap - used,
		                 ",\"album_observation\":{\"known\":false,\"reason\":\"not_observed\"}");
	} else {
		n = vau_snprintf(
		        out + used, cap - used,
		        ",\"album_observation\":{\"known\":true,\"link_count\":\"%llu\",\"list_count\":\"%llu\"}",
		        (unsigned long long)albums.links, (unsigned long long)albums.lists);
	}

	if (n < 0 || (size_t)n >= cap - used)
		return VAU_UNSUPPORTED;
	return (int)(used + (size_t)n);
}

int vau_content_snapshot_json(struct vau_content_journal *j,
                              const struct vau_content_delete_request *request, uint64_t scope,
                              uint64_t cursor, char *out, size_t cap)
{
	if (!out || !cap)
		return VAU_INVALID;

	out[0] = 0;
	if (!vau_content_delete_request_valid(request) || cursor > INT64_MAX)
		return VAU_INVALID;

	struct vau_content_scope header;
	int rc = vau_content_scope_get(j, scope, &header);

	if (rc)
		return rc == 1 ? VAU_STALE : rc;
	if (!same(request, &header.request))
		return VAU_DENIED;

	struct vau_content_scope_page page;

	rc = vau_content_scope_page(j, scope, cursor, &page);
	if (rc)
		return rc;

	char entry[2400] = "";
	uint64_t next    = cursor;
	int more         = 0;

	if (page.count) {
		int n = vau_content_scope_changes_json(
		        header.phase == VAU_CONTENT_SCOPE_AFTER ? NULL : &page.entries[0],
		        header.phase == VAU_CONTENT_SCOPE_AFTER ? &page.entries[0] : NULL, entry,
		        sizeof(entry));

		if (n < 0)
			return n;

		next = page.entries[0].sequence;
		more = page.more || page.count > 1;
	}

	static const char *const phases[] = { "preview", "before", "after" };

	char target[64];
	int rc_target = vau_content_target_json(request, target, sizeof(target));

	if (rc_target < 0)
		return rc_target;

	int n = vau_snprintf(
	        out, cap,
	        "{\"operation_id\":\"%s\"%s,\"scope_sequence\":\"%llu\",\"phase\":\"%s\","
	        "\"observed_us\":\"%llu\",\"path_count\":\"%llu\",\"entries\":[%s],\"next_cursor\":"
	        "\"%llu\",\"more\":%s}",
	        request->id, target, (unsigned long long)scope, phases[header.phase],
	        (unsigned long long)header.observed_us, (unsigned long long)header.path_count, entry,
	        (unsigned long long)next, more ? "true" : "false");

	if (n < 0 || (size_t)n >= cap) {
		out[0] = 0;
		return VAU_UNSUPPORTED;
	}

	if (request->kind >= VAU_CONTENT_PHOTO) {
		/* Replace the final brace, keeping all immutable metadata on every page. */
		size_t used = (size_t)n - 1;
		int extra   = media_metadata(j, scope, out + used, cap - used);

		if (extra < 0 || (size_t)extra + 2 > cap - used) {
			out[0] = 0;
			return extra < 0 ? extra : VAU_UNSUPPORTED;
		}

		used += (size_t)extra;
		out[used++] = '}';
		out[used]   = 0;
		n           = (int)used;
	}

	return n;
}

int vau_content_albums_json(struct vau_content_journal *j,
                            const struct vau_content_delete_request *request, uint64_t scope,
                            uint64_t link_cursor, uint64_t list_cursor, char *out, size_t cap)
{
	if (!out || !cap)
		return VAU_INVALID;

	out[0] = 0;
	if (!vau_content_delete_request_valid(request) || request->kind < VAU_CONTENT_PHOTO)
		return VAU_INVALID;

	struct vau_content_scope header;
	int rc = vau_content_scope_get(j, scope, &header);

	if (rc)
		return rc == 1 ? VAU_STALE : rc;
	if (!same(request, &header.request))
		return VAU_DENIED;

	struct vau_content_album_page page;

	rc = vau_content_scope_albums_page(j, scope, link_cursor, list_cursor, &page);
	if (rc)
		return rc;

	char target[64];

	rc = vau_content_target_json(request, target, sizeof(target));
	if (rc < 0)
		return rc;

	int n = vau_snprintf(
	        out, cap,
	        "{\"operation_id\":\"%s\"%s,\"scope_sequence\":\"%llu\",\"known\":%s,\"link_count\":"
	        "\"%llu\",\"list_count\":\"%llu\",\"links\":[",
	        request->id, target, (unsigned long long)scope, page.known ? "true" : "false",
	        (unsigned long long)page.set.links, (unsigned long long)page.set.lists);

	if (n < 0 || (size_t)n >= cap)
		goto overflow;

	size_t used = (size_t)n;

	for (unsigned i = 0; i < page.link_count; i++) {
		const struct vau_content_media_link *r = &page.links[i];

		n = vau_snprintf(out + used, cap - used,
		                 "%s{\"id\":\"%llu\",\"list_id\":\"%llu\",\"item_type\":%u}", i ? "," : "",
		                 (unsigned long long)r->id, (unsigned long long)r->list_id, r->item_type);
		if (n < 0 || (size_t)n >= cap - used)
			goto overflow;

		used += (size_t)n;
	}

	n = vau_snprintf(out + used, cap - used, "],\"lists\":[");
	if (n < 0 || (size_t)n >= cap - used)
		goto overflow;

	used += (size_t)n;
	for (unsigned i = 0; i < page.list_count; i++) {
		const struct vau_content_media_list *r = &page.lists[i];

		n = vau_snprintf(
		        out + used, cap - used,
		        "%s{\"id\":\"%llu\",\"registered\":%s,\"items\":\"%llu\",\"target_items\":\"%llu\"}",
		        i ? "," : "", (unsigned long long)r->id, r->registered ? "true" : "false",
		        (unsigned long long)r->items, (unsigned long long)r->target_items);
		if (n < 0 || (size_t)n >= cap - used)
			goto overflow;

		used += (size_t)n;
	}

	n = vau_snprintf(out + used, cap - used,
	                 "],\"next_cursor\":\"%llu\",\"next_list_cursor\":\"%llu\",\"more\":%s}",
	                 (unsigned long long)page.next_link, (unsigned long long)page.next_list,
	                 page.more ? "true" : "false");
	if (n < 0 || (size_t)n >= cap - used)
		goto overflow;
	return (int)(used + (size_t)n);
overflow:
	out[0] = 0;
	return VAU_UNSUPPORTED;
}
