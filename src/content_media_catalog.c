/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_media_catalog.h"
#include "format.h"
#include "native_ops.h"
#include <limits.h>
#include <string.h>

#ifdef VAU_NATIVE_FORMAT
#include "sqlite_memory.h"

/* Raw SQLite result codes and the -65536 error encoding: see sqlite_api.h. */
#endif

static int media_links_number(sqlite3_stmt *s, int column, uint64_t *out)
{
	if (sqlite3_column_type(s, column) != 1)
		return VAU_DEVICE_ERROR;

	const unsigned char *p = sqlite3_column_text(s, column);
	int size               = sqlite3_column_bytes(s, column);

	if (!p || size < 1 || size > 19)
		return VAU_DEVICE_ERROR;

	uint64_t value = 0;

	for (int i = 0; i < size; i++) {
		if (p[i] < '0' || p[i] > '9' || value > ((uint64_t)INT64_MAX - (unsigned)(p[i] - '0')) / 10)
			return VAU_DEVICE_ERROR;

		value = value * 10 + (unsigned)(p[i] - '0');
	}

	*out = value;
	return 0;
}

static int media_links_bind(sqlite3_stmt *s, int index, uint64_t id, char *text, size_t cap)
{
	int n = vau_snprintf(text, cap, "%llu", (unsigned long long)id);

	if (n < 1 || (size_t)n >= cap)
		return VAU_INVALID;

	int rc = sqlite3_bind_text(s, index, text, n, NULL);

	return rc ? -65536 - rc : 0;
}

static int media_links_finish(sqlite3_stmt *s, int rc)
{
	if (s) {
		int end = sqlite3_finalize(s);

		if (!rc && end)
			rc = -65536 - end;
	}

	return rc;
}

int vau_content_media_links(sqlite3 *db, uint64_t id, vau_content_media_link_visit visit,
                            void *context)
{
	if (!db || !id || id > INT64_MAX || !visit)
		return VAU_INVALID;

	sqlite3_stmt *s = NULL;
	int rc          = sqlite3_prepare_v2(db,
	                                     "SELECT id,list_id,item_type FROM tbl_AVContentItem "
	                                              "WHERE item_id=CAST(?1 AS INTEGER) ORDER BY id",
	                                     -1, &s, NULL);

	if (rc)
		rc = -65536 - rc;

	char text[24];

	if (!rc)
		rc = media_links_bind(s, 1, id, text, sizeof(text));

	uint64_t previous = 0;

	while (!rc) {
		int step = sqlite3_step(s);

		if (step == 101)
			break;
		if (step != 100) {
			rc = -65536 - step;
			break;
		}

		struct vau_content_media_link link = { 0 };
		uint64_t type                      = 0;

		rc = media_links_number(s, 0, &link.id);
		if (!rc)
			rc = media_links_number(s, 1, &link.list_id);
		if (!rc)
			rc = media_links_number(s, 2, &type);
		if (!rc && (link.id <= previous || type > UINT_MAX))
			rc = VAU_DEVICE_ERROR;
		if (!rc) {
			link.item_type = (unsigned)type;
			previous       = link.id;
			rc             = visit(context, &link);
		}
	}

	return media_links_finish(s, rc);
}

int vau_content_media_list(sqlite3 *db, uint64_t list, uint64_t target,
                           struct vau_content_media_list *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!db || list > INT64_MAX || !target || target > INT64_MAX)
		return VAU_INVALID;

	sqlite3_stmt *s = NULL;
	int rc          = sqlite3_prepare_v2(
            db,
            "SELECT "
	                 "(SELECT count(*) FROM tbl_AVContentList WHERE mrid=CAST(?1 AS INTEGER)),"
	                 "count(*),COALESCE(sum(CASE WHEN item_id=CAST(?2 AS INTEGER) THEN 1 ELSE "
	                 "0 END),0) "
	                 "FROM tbl_AVContentItem WHERE list_id=CAST(?1 AS INTEGER)",
            -1, &s, NULL);
	if (rc)
		rc = -65536 - rc;
	char list_text[24], target_text[24];
	if (!rc)
		rc = media_links_bind(s, 1, list, list_text, sizeof(list_text));
	if (!rc)
		rc = media_links_bind(s, 2, target, target_text, sizeof(target_text));

	struct vau_content_media_list found = { .id = list };
	uint64_t registered                 = 0;

	if (!rc) {
		int step = sqlite3_step(s);

		if (step != 100)
			rc = step == 101 ? VAU_DEVICE_ERROR : -65536 - step;
		if (!rc)
			rc = media_links_number(s, 0, &registered);
		if (!rc)
			rc = media_links_number(s, 1, &found.items);
		if (!rc)
			rc = media_links_number(s, 2, &found.target_items);
		if (!rc && (registered > 1 || found.target_items > found.items))
			rc = VAU_DEVICE_ERROR;
		if (!rc) {
			found.registered = (unsigned)registered;
			step             = sqlite3_step(s);
			if (step != 101)
				rc = step == 100 ? VAU_DEVICE_ERROR : -65536 - step;
		}
	}

	rc = media_links_finish(s, rc);
	if (!rc)
		*out = found;
	return rc;
}

static int media_source_error(int rc)
{
	return rc ? -65536 - rc : 0;
}

int vau_media_source_close(struct vau_media_source *source)
{
	if (!source)
		return VAU_INVALID;

	source->ready = 0;
	if (!source->db) {
		memset(source, 0, sizeof(*source));
		return 0;
	}

	int rc = 0;

	if (source->transaction) {
		rc = media_source_error(sqlite3_exec(source->db, "ROLLBACK", NULL, NULL, NULL));
		if (!rc)
			source->transaction = 0;
	}

	int end = media_source_error(sqlite3_close(source->db));

	if (!end)
		memset(source, 0, sizeof(*source));
	return rc ? rc : end;
}

int vau_media_source_open(struct vau_media_source *source, const char *path, unsigned category)
{
	if (!source || !path || !path[0] || category < 1 || category > 3)
		return VAU_INVALID;
	if (source->db)
		return VAU_BUSY;
	if (source->ready || source->transaction)
		return VAU_INVALID;

	source->category = category;

	int rc = media_source_error(sqlite3_open_v2(path, &source->db, 1, NULL));

	if (!rc)
		rc = media_source_error(sqlite3_exec(source->db, "PRAGMA cache_size=32", NULL, NULL, NULL));
	if (!rc) {
		rc = media_source_error(sqlite3_exec(source->db, "BEGIN", NULL, NULL, NULL));
		if (!rc)
			source->transaction = 1;
	}

	if (rc) {
		(void)vau_media_source_close(source); /* Keep a handle if cleanup needs retry. */
		return rc;
	}

	source->ready = 1;
	return 0;
}

int vau_vita_media_source_open(struct vau_media_source *source, unsigned category)
{
	if (!source || category < 1 || category > 3)
		return VAU_INVALID;
	if (source->db)
		return VAU_BUSY;
#ifdef VAU_NATIVE_FORMAT
	int rc = vau_sqlite_memory_configure();
	if (rc)
		return rc;
#endif
	static const char *const paths[] = {
		"ux0:/mms/photo/AVContent.db",
		"ux0:/mms/music/AVContent.db",
		"ux0:/mms/video/AVContent.db",
	};
	return vau_media_source_open(source, paths[category - 1], category);
}

static int media_record_number(sqlite3_stmt *s, int column, uint64_t *out)
{
	if (sqlite3_column_type(s, column) != 1)
		return VAU_DEVICE_ERROR;

	const unsigned char *p = sqlite3_column_text(s, column);
	int bytes              = sqlite3_column_bytes(s, column);

	if (!p || bytes < 1 || bytes > 19)
		return VAU_DEVICE_ERROR;

	uint64_t value = 0;

	for (int i = 0; i < bytes; i++) {
		if (p[i] < '0' || p[i] > '9' || value > ((uint64_t)INT64_MAX - (unsigned)(p[i] - '0')) / 10)
			return VAU_DEVICE_ERROR;

		value = value * 10 + (unsigned)(p[i] - '0');
	}

	*out = value;
	return 0;
}

int vau_content_media_record(sqlite3 *db, unsigned category, uint64_t id,
                             struct vau_content_media_record *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!db || category < 1 || category > 3 || !id || id > INT64_MAX)
		return VAU_INVALID;

	static const char *const queries[] = {
		"SELECT mrid,content_path,size,status,content_type FROM tbl_VPContent "
		"WHERE mrid=CAST(?1 AS INTEGER) "
		"LIMIT 2",
		"SELECT mrid,content_path,size,status,0 FROM tbl_Music WHERE "
		"mrid=CAST(?1 AS INTEGER) LIMIT 2",
		"SELECT mrid,content_path,size,status,content_type FROM tbl_VPContent "
		"WHERE mrid=CAST(?1 AS INTEGER) "
		"LIMIT 2",
	};

	sqlite3_stmt *s = NULL;
	int rc          = sqlite3_prepare_v2(db, queries[category - 1], -1, &s, NULL);

	if (rc)
		rc = -65536 - rc;

	char value[24];

	vau_snprintf(value, sizeof(value), "%llu", (unsigned long long)id);
	if (!rc) {
		rc = sqlite3_bind_text(s, 1, value, -1, NULL);
		if (rc)
			rc = -65536 - rc;
	}

	struct vau_content_media_record found = { 0 };

	if (!rc) {
		int step = sqlite3_step(s);

		if (step == 101) {
			rc = 1;
		} else if (step != 100) {
			rc = -65536 - step;
		} else {
			rc = media_record_number(s, 0, &found.id);

			uint64_t status = 0, type = 0;

			if (!rc)
				rc = media_record_number(s, 3, &status);
			if (!rc)
				rc = media_record_number(s, 4, &type);
			if (!rc && (found.id != id || status > UINT32_MAX))
				rc = VAU_DEVICE_ERROR;
			if (!rc && type != (category == 1 ? 4u : category == 3 ? 5u : 0u))
				rc = VAU_STALE;
			if (!rc && sqlite3_column_type(s, 2) != 5) {
				rc = media_record_number(s, 2, &found.bytes);
				if (!rc)
					found.bytes_known = 1;
			}

			if (!rc && sqlite3_column_type(s, 1) != 3)
				rc = VAU_DEVICE_ERROR;
			if (!rc) {
				const unsigned char *path = sqlite3_column_text(s, 1);
				int bytes                 = sqlite3_column_bytes(s, 1);

				if (!path || bytes < 1 || (size_t)bytes >= sizeof(found.path) ||
				    memchr(path, 0, (size_t)bytes)) {
					rc = VAU_DEVICE_ERROR;
				} else {
					memcpy(found.path, path, (size_t)bytes);
					found.path[bytes] = 0;
					found.category    = category;
					found.status      = (unsigned)status;
				}
			}

			if (!rc) {
				step = sqlite3_step(s);
				if (step != 101)
					rc = step == 100 ? VAU_STALE : -65536 - step;
			}
		}
	}

	if (s) {
		int end = sqlite3_finalize(s);

		if ((rc == 0 || rc == 1) && end)
			rc = -65536 - end;
	}

	if (!rc)
		*out = found;
	return rc;
}

int vau_vita_content_media_record(unsigned category, uint64_t id,
                                  struct vau_content_media_record *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (category < 1 || category > 3 || !id || id > INT64_MAX)
		return VAU_INVALID;

	struct vau_media_source source = { 0 };
	int rc                         = vau_vita_media_source_open(&source, category);
	struct vau_content_media_record found;

	if (!rc)
		rc = vau_content_media_record(source.db, source.category, id, &found);

	int end = vau_media_source_close(&source);

	if ((rc == 0 || rc == 1) && end)
		rc = end;
	if (!rc)
		*out = found;
	return rc;
}
