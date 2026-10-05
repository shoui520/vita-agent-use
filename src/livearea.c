/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "native_ops.h"
#include "sqlite_api.h"
#include "json.h"
#include "format.h"
#include <string.h>

#ifdef VAU_NATIVE_FORMAT
#include "sqlite_memory.h"

/* Raw SQLite result codes and the -65536 error encoding: see sqlite_api.h. */
#endif
int vau_livearea_schema(const char *path, const char *after, char *out, size_t cap)
{
	if (!path || !after || !out || strlen(after) >= 32)
		return VAU_INVALID;
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return configured;
#endif
	sqlite3 *db = NULL;

	sqlite3_stmt *statement = NULL;
	int n                   = 0;
	int rc                  = sqlite3_open_v2(path, &db, 1, NULL);

	if (rc)
		goto done;

	rc = sqlite3_exec(db, "PRAGMA cache_size=32", NULL, NULL, NULL);
	if (rc)
		goto done;

	rc = sqlite3_prepare_v2(
	        db,
	        "SELECT name,sql FROM sqlite_master WHERE type='table' AND name>?1 ORDER BY name LIMIT 2",
	        -1, &statement, NULL);
	if (rc)
		goto done;

	rc = sqlite3_bind_text(statement, 1, after, -1, NULL);
	if (rc)
		goto done;

	n = vau_snprintf(
	        out, cap,
	        "{\"source\":\"native_sqlite_readonly\",\"path\":\"ur0:shell/db/app.db\",\"entries\":[");
	if (n < 0 || (size_t)n >= cap) {
		rc = VAU_DEVICE_ERROR;
		goto done;
	}

	char next[32] = { 0 };

	memcpy(next, after, strlen(after) + 1);

	unsigned count = 0, more = 0;

	while ((rc = sqlite3_step(statement)) == 100) {
		if (count) {
			more = 1;
			rc   = 0;
			break;
		}

		const unsigned char *name   = sqlite3_column_text(statement, 0),
		                    *schema = sqlite3_column_text(statement, 1);
		int name_bytes              = sqlite3_column_bytes(statement, 0),
		    schema_bytes            = sqlite3_column_bytes(statement, 1);

		if (!name || !schema || name_bytes < 1 || name_bytes >= 32 || schema_bytes < 1 ||
		    schema_bytes > 3000 || memchr(name, 0, name_bytes) || memchr(schema, 0, schema_bytes)) {
			rc = VAU_UNSUPPORTED;
			goto done;
		}

		char quoted_name[195], sql[6003];

		if (vau_json_quote((const char *)name, quoted_name, sizeof(quoted_name)) < 0 ||
		    vau_json_quote((const char *)schema, sql, sizeof(sql)) < 0) {
			rc = VAU_DEVICE_ERROR;
			goto done;
		}

		int added = vau_snprintf(out + n, cap - (size_t)n, "{\"name\":%s,\"schema\":%s}",
		                         quoted_name, sql);

		if (added < 0 || (size_t)added + 100 >= cap - (size_t)n) {
			rc = VAU_UNSUPPORTED;
			goto done;
		}

		n += added;
		memcpy(next, name, name_bytes);
		next[name_bytes] = 0;
		count++;
	}

	if (rc == 101)
		rc = 0;
	if (!rc) {
		char cursor[195];

		if (vau_json_quote(next, cursor, sizeof(cursor)) < 0) {
			rc = VAU_DEVICE_ERROR;
			goto done;
		}

		int added = vau_snprintf(out + n, cap - (size_t)n, "],\"next_after\":%s,\"more\":%s}",
		                         cursor, more ? "true" : "false");

		if (added < 0 || (size_t)added >= cap - (size_t)n)
			rc = VAU_DEVICE_ERROR;
		else
			n += added;
	}
done:
	if (statement) {
		int end = sqlite3_finalize(statement);

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

int vau_vita_livearea_schema(void *context, const char *after, char *out, size_t cap)
{
	(void)context;
	return vau_livearea_schema("ur0:shell/db/app.db", after, out, cap);
}
