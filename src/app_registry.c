/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "app_registry.h"
#include "vita_agent.h"
#include <string.h>

#ifdef VAU_NATIVE_FORMAT
#include "sqlite_memory.h"
#endif
#include "sqlite_api.h"

static const char *const install_fields[VAU_APP_INSTALL_FIELDS] = {
	"_org_path",
	"INSTALL_DIR_SAVEDATA",
	"INSTALL_DIR_CACHE0",
	"INSTALL_DIR_ADDCONT",
	"INSTALL_DIR_ADDCONT_ADD_1",
	"INSTALL_DIR_ADDCONT_ADD_2",
	"INSTALL_DIR_ADDCONT_ADD_3",
	"INSTALL_DIR_ADDCONT_ADD_4",
	"INSTALL_DIR_ADDCONT_ADD_5",
	"INSTALL_DIR_ADDCONT_ADD_6",
	"INSTALL_DIR_ADDCONT_ADD_7",
};

/* Native FNV-1a keys, independently checked against TITLE/CATEGORY/_org_path
 * and the 3.65 uninstall backend's literal metadata keys. */
static const uint32_t install_keys[VAU_APP_INSTALL_FIELDS] = {
	2593862978u, 278217076u, 904872283u, 4045363504u, 71174776u,  121507633u,
	104730014u,  155062871u, 138285252u, 188618109u,  171840490u,
};

const char *vau_app_install_field(unsigned i)
{
	return i < VAU_APP_INSTALL_FIELDS ? install_fields[i] : NULL;
}

static int column(sqlite3_stmt *s, int index, char *out, size_t capacity)
{
	const unsigned char *text = sqlite3_column_text(s, index);
	int bytes                 = sqlite3_column_bytes(s, index);

	if (bytes < 0 || (size_t)bytes >= capacity || (bytes && !text) ||
	    (text && memchr(text, 0, (size_t)bytes))) {
		return VAU_DEVICE_ERROR;
	}

	if (bytes)
		memcpy(out, text, (size_t)bytes);
	out[bytes] = 0;
	return VAU_OK;
}

int vau_app_registry_read(const char *path, const char *after, const char *query,
                          struct vau_app_page *out)
{
	if (!path || !after || !query || !out || strlen(after) >= VAU_APP_ID_BYTES ||
	    strlen(query) >= VAU_APP_QUERY_BYTES) {
		return VAU_INVALID;
	}

	char cursor[VAU_APP_ID_BYTES], search[VAU_APP_QUERY_BYTES];

	memcpy(cursor, after, strlen(after) + 1);
	memcpy(search, query, strlen(query) + 1);
	memset(out, 0, sizeof(*out));
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return configured;
#endif
	sqlite3 *db = NULL;

	sqlite3_stmt *statement = NULL;

	/* Native TITLE/CATEGORY keys from the app registry. Filtering the TITLE
	 * records avoids icon-only folder entries and duplicate metadata rows. */
	const char *sql =
	        "SELECT a.titleId,a.val,COALESCE(c.val,'') FROM tbl_appinfo a "
	        "LEFT JOIN tbl_appinfo c ON c.titleId=a.titleId AND c.key=566916785 "
	        "WHERE a.key=572932585 AND a.titleId>?1 AND (?2='%%' OR a.val LIKE ?2 ESCAPE '\\') "
	        "ORDER BY a.titleId LIMIT 3";
	char pattern[VAU_APP_QUERY_BYTES * 2 + 3];
	size_t used = 0;

	pattern[used++] = '%';
	for (const char *p = search; *p; p++) {
		if (*p == '%' || *p == '_' || *p == '\\')
			pattern[used++] = '\\';
		pattern[used++] = *p;
	}

	pattern[used++] = '%';
	pattern[used]   = 0;

	int rc = sqlite3_open_v2(path, &db, 1, NULL); /* SQLITE_OPEN_READONLY */
	if (rc)
		goto done;

	/* Connection-local page cache, not a write to the registry. */
	rc = sqlite3_exec(db, "PRAGMA cache_size=32", NULL, NULL, NULL);
	if (rc)
		goto done;

	rc = sqlite3_prepare_v2(db, sql, -1, &statement, NULL);
	if (rc)
		goto done;

	rc = sqlite3_bind_text(statement, 1, cursor, -1, NULL);
	if (rc)
		goto done;

	rc = sqlite3_bind_text(statement, 2, pattern, -1, NULL);
	if (rc)
		goto done;

	while ((rc = sqlite3_step(statement)) == 100) { /* SQLITE_ROW */
		if (out->count == VAU_APP_PAGE_ENTRIES) {
			out->more = 1;
			rc        = 0;
			break;
		}

		struct vau_app_entry *entry = &out->entries[out->count];

		rc = column(statement, 0, entry->title_id, sizeof(entry->title_id));
		if (rc)
			goto done;

		rc = column(statement, 1, entry->name, sizeof(entry->name));
		if (rc)
			goto done;

		rc = column(statement, 2, entry->category, sizeof(entry->category));
		if (rc)
			goto done;
		if (!entry->title_id[0] || strcmp(entry->title_id, cursor) <= 0) {
			rc = VAU_DEVICE_ERROR;
			goto done;
		}

		memcpy(out->next_after, entry->title_id, sizeof(out->next_after));
		out->count++;
	}

	if (rc == 101)
		rc = 0; /* SQLITE_DONE */
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

	if (rc)
		memset(out, 0, sizeof(*out));
	return rc;
}

int vau_vita_app_list(void *context, const char *after, const char *query, struct vau_app_page *out)
{
	(void)context;
	return vau_app_registry_read("ur0:shell/db/app.db", after, query, out);
}

int vau_app_registry_find(const char *path, const char *title, struct vau_app_entry *out)
{
	if (!path || !title || !out || !*title || strlen(title) >= VAU_APP_ID_BYTES)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return -65536 - configured;
#endif
	sqlite3 *db = NULL;

	sqlite3_stmt *s            = NULL;
	struct vau_app_entry entry = { 0 };
	int rc = sqlite3_open_v2(path, &db, 1, NULL), found = 0;

	if (!rc)
		rc = sqlite3_exec(db, "PRAGMA cache_size=16", NULL, NULL, NULL);
	if (!rc) {
		rc = sqlite3_prepare_v2(
		        db,
		        "SELECT a.titleId,a.val,COALESCE(c.val,'') FROM tbl_appinfo a "
		        "LEFT JOIN tbl_appinfo c ON c.titleId=a.titleId AND c.key=566916785 "
		        "WHERE a.key=572932585 AND a.titleId=?1 LIMIT 2",
		        -1, &s, NULL);
	}

	if (!rc)
		rc = sqlite3_bind_text(s, 1, title, -1, NULL);
	if (!rc) {
		int step = sqlite3_step(s);

		if (step == 100) {
			rc = column(s, 0, entry.title_id, sizeof(entry.title_id));
			if (!rc)
				rc = column(s, 1, entry.name, sizeof(entry.name));
			if (!rc)
				rc = column(s, 2, entry.category, sizeof(entry.category));
			if (!rc && strcmp(entry.title_id, title))
				rc = VAU_DEVICE_ERROR;
			if (!rc) {
				step = sqlite3_step(s);
				if (step == 101)
					found = 1;
				else
					rc = step == 100 ? VAU_DEVICE_ERROR : step;
			}
		} else if (step != 101) {
			rc = step;
		}
	}

	if (s) {
		int end = sqlite3_finalize(s);

		if (!rc)
			rc = end;
	}

	if (db) {
		int end = sqlite3_close(db);

		if (!rc)
			rc = end;
	}

	if (rc)
		return rc < 0 ? rc : -65536 - rc;
	if (found)
		*out = entry;
	return found ? VAU_OK : 1;
}

int vau_app_registry_install_metadata(const char *path, const char *title,
                                      struct vau_app_install_metadata *out)
{
	if (!path || !title || !out || !*title || strlen(title) >= VAU_APP_ID_BYTES)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return -65536 - configured;
#endif
	sqlite3 *db = NULL;

	sqlite3_stmt *s = NULL;
	int rc          = sqlite3_open_v2(path, &db, 1, NULL);

	if (!rc)
		rc = sqlite3_exec(db, "PRAGMA cache_size=16", NULL, NULL, NULL);
	if (!rc) {
		rc = sqlite3_prepare_v2(
		        db,
		        "SELECT key,val,typeof(val) FROM tbl_appinfo WHERE titleId=?1 AND key IN("
		        "2593862978,278217076,904872283,4045363504,71174776,121507633,104730014,155062871,138285252,188618109,171840490) "
		        "ORDER BY key LIMIT 12",
		        -1, &s, NULL);
	}

	if (!rc)
		rc = sqlite3_bind_text(s, 1, title, -1, NULL);
	if (!rc) {
		for (;;) {
			int step = sqlite3_step(s);

			if (step == 101)
				break;
			if (step != 100) {
				rc = step;
				break;
			}

			char key[16], type[16];

			rc = column(s, 0, key, sizeof(key));
			if (rc)
				break;

			rc = column(s, 2, type, sizeof(type));
			if (rc)
				break;
			if (strcmp(type, "text")) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			uint64_t value = 0;
			unsigned i;

			if (!key[0]) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			for (const char *p = key; *p; p++) {
				if (*p < '0' || *p > '9' || value > UINT32_MAX / 10 ||
				    (value == UINT32_MAX / 10 && (unsigned)(*p - '0') > UINT32_MAX % 10)) {
					rc = VAU_DEVICE_ERROR;
					break;
				}

				value = value * 10 + (unsigned)(*p - '0');
			}

			if (rc)
				break;

			for (i = 0; i < VAU_APP_INSTALL_FIELDS && install_keys[i] != value; i++) {
			}

			if (i == VAU_APP_INSTALL_FIELDS || (out->present & (1u << i))) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			rc = column(s, 1, out->values[i], sizeof(out->values[i]));
			if (rc)
				break;

			out->present |= 1u << i;
		}
	}

	if (s) {
		int end = sqlite3_finalize(s);

		if (!rc)
			rc = end;
	}

	if (db) {
		int end = sqlite3_close(db);

		if (!rc)
			rc = end;
	}

	if (rc) {
		memset(out, 0, sizeof(*out));
		return rc < 0 ? rc : -65536 - rc;
	}

	return out->present ? VAU_OK : 1;
}

int vau_app_registry_savedata_shared(const char *path, const char *title, const char *savedata,
                                     int *out)
{
	if (!path || !title || !savedata || !out || !*title || !*savedata ||
	    strlen(title) >= VAU_APP_ID_BYTES || strlen(savedata) >= VAU_APP_INSTALL_VALUE_BYTES) {
		return VAU_INVALID;
	}

	*out = 0;
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return -65536 - configured;
#endif
	sqlite3 *db = NULL;

	sqlite3_stmt *s = NULL;
	int rc = sqlite3_open_v2(path, &db, 1, NULL), shared = 0;

	if (!rc)
		rc = sqlite3_exec(db, "PRAGMA cache_size=16", NULL, NULL, NULL);
	if (!rc) {
		rc = sqlite3_prepare_v2(
		        db,
		        "SELECT titleId FROM tbl_appinfo WHERE key=278217076 AND val=?1 AND titleId<>?2 LIMIT 1",
		        -1, &s, NULL);
	}

	if (!rc)
		rc = sqlite3_bind_text(s, 1, savedata, -1, NULL);
	if (!rc)
		rc = sqlite3_bind_text(s, 2, title, -1, NULL);
	if (!rc) {
		int step = sqlite3_step(s);

		if (step == 100) {
			char other[VAU_APP_ID_BYTES];

			rc = column(s, 0, other, sizeof(other));
			if (!rc && (!other[0] || !strcmp(other, title)))
				rc = VAU_DEVICE_ERROR;
			if (!rc)
				shared = 1;
		} else if (step != 101) {
			rc = step;
		}
	}

	if (s) {
		int end = sqlite3_finalize(s);

		if (!rc)
			rc = end;
	}

	if (db) {
		int end = sqlite3_close(db);

		if (!rc)
			rc = end;
	}

	if (rc)
		return rc < 0 ? rc : -65536 - rc;

	*out = shared;
	return VAU_OK;
}

int vau_app_registry_gamedata(const char *path, const char *title,
                              char out[VAU_APP_INSTALL_VALUE_BYTES], int *shared)
{
	if (!out || !shared)
		return VAU_INVALID;

	memset(out, 0, VAU_APP_INSTALL_VALUE_BYTES);
	*shared = 0;
	if (!path || !title || !*title || strlen(title) >= VAU_APP_ID_BYTES)
		return VAU_INVALID;
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return -65536 - configured;
#endif
	sqlite3 *db = NULL;

	sqlite3_stmt *s = NULL;
	int rc = sqlite3_open_v2(path, &db, 1, NULL), rows = 0;

	if (!rc)
		rc = sqlite3_exec(db, "PRAGMA cache_size=16", NULL, NULL, NULL);
	if (!rc) {
		rc = sqlite3_prepare_v2(
		        db,
		        "SELECT a.val,typeof(a.val),EXISTS(SELECT 1 FROM tbl_appinfo b WHERE "
		        "b.key=2454440077 AND b.val=a.val AND b.titleId<>?1) FROM tbl_appinfo a "
		        "WHERE a.titleId=?1 AND a.key=2454440077 LIMIT 2",
		        -1, &s, NULL);
	}

	if (!rc)
		rc = sqlite3_bind_text(s, 1, title, -1, NULL);
	if (!rc) {
		for (;;) {
			int step = sqlite3_step(s);

			if (step == 101)
				break;
			if (step != 100) {
				rc = step;
				break;
			}

			if (rows++) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			char type[16], flag[4];

			rc = column(s, 1, type, sizeof(type));
			if (rc)
				break;
			if (strcmp(type, "text")) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			rc = column(s, 0, out, VAU_APP_INSTALL_VALUE_BYTES);
			if (rc)
				break;

			rc = column(s, 2, flag, sizeof(flag));
			if (rc)
				break;
			if (strcmp(flag, "0") && strcmp(flag, "1")) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			*shared = out[0] && flag[0] == '1';
		}
	}

	if (s) {
		int end = sqlite3_finalize(s);

		if (!rc)
			rc = end;
	}

	if (db) {
		int end = sqlite3_close(db);

		if (!rc)
			rc = end;
	}

	if (rc) {
		memset(out, 0, VAU_APP_INSTALL_VALUE_BYTES);
		*shared = 0;
		return rc < 0 ? rc : -65536 - rc;
	}

	return VAU_OK;
}
