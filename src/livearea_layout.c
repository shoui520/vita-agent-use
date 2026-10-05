/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "native_ops.h"
#include "sqlite_json.h"
#include "format.h"
#include <string.h>

#ifdef VAU_NATIVE_FORMAT
#include "sqlite_memory.h"
#endif
int vau_livearea_layout(const char *path, const char *section, uint32_t offset, char *out,
                        size_t cap)
{
	if (!path || !section || !out || cap < 3500 || offset > 100000)
		return VAU_INVALID;

	int icons = !strcmp(section, "icons");

	if (!icons && strcmp(section, "pages"))
		return VAU_INVALID;
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return configured;
#endif
	/* Columns confirmed by the real native Shell schema, recorded privately.
	 * Folder/page relationships are returned raw; no database mutation. */
	const char *sql =
	        icons ? "SELECT pageId,pos,iconPath,title,type,command,titleId,icon0Type,parentalLockLv,status,reserved01,reserved02,reserved03,reserved04,reserved05 FROM tbl_appinfo_icon ORDER BY pageId,pos LIMIT 2 OFFSET CAST(?1 AS INTEGER)"
	              : "SELECT pageId,pageNo,themeFile,bgColor,texWidth,texHeight,imageWidth,imageHeight,reserved01,reserved02,reserved03,reserved04,reserved05 FROM tbl_appinfo_page ORDER BY pageNo,pageId LIMIT 2 OFFSET CAST(?1 AS INTEGER)";
	static const char *page_fields[] = {
		"page_id",        "page_no",     "theme_file",   "background_color", "texture_width",
		"texture_height", "image_width", "image_height", "reserved01",       "reserved02",
		"reserved03",     "reserved04",  "reserved05",
	};
	static const char *icon_fields[] = {
		"page_id",    "position",   "icon_path",           "title",  "type",       "command",
		"title_id",   "icon0_type", "parental_lock_level", "status", "reserved01", "reserved02",
		"reserved03", "reserved04", "reserved05",
	};

	const char *const *fields = icons ? icon_fields : page_fields;

	unsigned columns = icons ? 15 : 13;

	vau_sqlite_json_reset();

	sqlite3 *db        = NULL;
	sqlite3_stmt *stmt = NULL;
	int n              = 0;
	unsigned count = 0, more = 0;
	int rc = sqlite3_open_v2(path, &db, 1, NULL);

	if (rc)
		goto done;

	rc = sqlite3_exec(db, "PRAGMA cache_size=32", NULL, NULL, NULL);
	if (rc)
		goto done;

	rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	if (rc)
		goto done;

	char cursor[16];

	vau_snprintf(cursor, sizeof(cursor), "%u", offset);
	rc = sqlite3_bind_text(stmt, 1, cursor, -1, NULL);
	if (rc)
		goto done;

	n = vau_snprintf(
	        out, cap,
	        "{\"source\":\"native_livearea_database\",\"path\":\"ur0:shell/db/app.db\",\"section\":\"%s\",\"snapshot\":false,\"entries\":[",
	        section);
	if (n < 0 || (size_t)n >= cap) {
		rc = VAU_DEVICE_ERROR;
		goto done;
	}

	while ((rc = sqlite3_step(stmt)) == 100) {
		if (count) {
			more = 1;
			rc   = 0;
			break;
		}

		if ((size_t)n + 2 >= cap) {
			rc = VAU_UNSUPPORTED;
			goto done;
		}

		out[n++] = '{';
		for (unsigned i = 0; i < columns; i++) {
			int added =
			        vau_snprintf(out + n, cap - (size_t)n, "%s\"%s\":", i ? "," : "", fields[i]);

			if (added < 0 || (size_t)added >= cap - (size_t)n) {
				rc = VAU_UNSUPPORTED;
				goto done;
			}

			n += added;
			added = vau_sqlite_json_column(stmt, (int)i, out + n, cap - (size_t)n, i == 0);
			if (added < 0) {
				rc = added;
				goto done;
			}

			n += added;
			if ((size_t)n + 100 >= cap) {
				rc = VAU_UNSUPPORTED;
				goto done;
			}
		}

		out[n++] = '}';
		count++;
	}

	if (rc == 101)
		rc = 0;
	if (!rc) {
		int added = vau_snprintf(out + n, cap - (size_t)n, "],\"next_offset\":%u,\"more\":%s}",
		                         offset + count, more ? "true" : "false");

		if (added < 0 || (size_t)added >= cap - (size_t)n)
			rc = VAU_DEVICE_ERROR;
		else
			n += added;
	}
done:
	if (stmt) {
		int end = sqlite3_finalize(stmt);

		if (!rc && end)
			rc = end;
	}

	if (db) {
		int end = sqlite3_close(db);

		if (!rc && end)
			rc = end;
	}

	return rc ? rc < 0 ? rc : VAU_DEVICE_ERROR : n;
}

int vau_vita_livearea_layout(void *ctx, const char *section, uint32_t offset, char *out, size_t cap)
{
	(void)ctx;
	return vau_livearea_layout("ur0:shell/db/app.db", section, offset, out, cap);
}
