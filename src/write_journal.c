/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "write_journal.h"
#include "format.h"
#include <string.h>
#include <limits.h>

#ifdef VAU_NATIVE_FORMAT
#include "sqlite_memory.h"
#include "sqlite_vfs.h"
#endif
static int error(int rc)
{
	return rc ? -65536 - rc : VAU_OK;
}

static int exec(sqlite3 *db, const char *sql)
{
	return error(sqlite3_exec(db, sql, NULL, NULL, NULL));
}

static int prepare(sqlite3 *db, const char *sql, sqlite3_stmt **s)
{
	return error(sqlite3_prepare_v2(db, sql, -1, s, NULL));
}

static int text(sqlite3_stmt *s, int i, const char *value)
{
	return error(sqlite3_bind_text(s, i, value, -1, NULL));
}

static int number(sqlite3_stmt *s, int i, uint64_t value, char storage[24])
{
	int n = vau_snprintf(storage, 24, "%llu", (unsigned long long)value);

	return n > 0 && n < 24 ? text(s, i, storage) : VAU_DEVICE_ERROR;
}

static int column(sqlite3_stmt *s, int i, char *out, size_t capacity)
{
	const unsigned char *p = sqlite3_column_text(s, i);
	int bytes              = sqlite3_column_bytes(s, i);

	if (bytes < 0 || !p || (size_t)bytes >= capacity || memchr(p, 0, (size_t)bytes))
		return VAU_DEVICE_ERROR;

	memcpy(out, p, (size_t)bytes);
	out[bytes] = 0;
	return VAU_OK;
}

static int integer(sqlite3_stmt *s, int i, uint64_t max, uint64_t *out)
{
	char p[24];
	int rc = column(s, i, p, sizeof(p));

	if (rc)
		return rc;
	if (!*p)
		return VAU_DEVICE_ERROR;

	uint64_t value = 0;

	for (unsigned j = 0; p[j]; ++j) {
		if (p[j] < '0' || p[j] > '9' || value > max / 10 ||
		    (value == max / 10 && (unsigned)(p[j] - '0') > max % 10)) {
			return VAU_DEVICE_ERROR;
		}

		value = value * 10 + (unsigned)(p[j] - '0');
	}

	*out = value;
	return VAU_OK;
}

static int request_valid(const struct vau_write_request *);

static int observation_valid(const struct vau_write_observation *s)
{
	return s->bytes <= INT64_MAX &&
	       (s->state == VAU_STATE_UNKNOWN || s->state == VAU_STATE_MISSING
	                ? !s->bytes
	                : s->state == VAU_STATE_OTHER || s->state == VAU_STATE_FILE ||
	                          s->state == VAU_STATE_DIRECTORY);
}

static const char fields[] =
        "sequence,subject,operation_id,phase,operation,path,destination,yes,recursive,overwrite,bytes,sha256,expected_sha256,result,effect_started,readback_required,observed_us,offset,detail,trash_id,detail_path,effect_path,before_state,before_bytes,after_state,after_bytes,destination_before_state,destination_before_bytes,destination_after_state,destination_after_bytes";

static int decode(sqlite3_stmt *s, struct vau_write_record *r)
{
	memset(r, 0, sizeof(*r));

	uint64_t value;
	int rc;
#define NUM(i, max, target)              \
	do {                                 \
		rc = integer(s, i, max, &value); \
		if (rc)                          \
			return rc;                   \
		target = value;                  \
	} while (0)
#define STR(i, target)                             \
	do {                                           \
		rc = column(s, i, target, sizeof(target)); \
		if (rc)                                    \
			return rc;                             \
	} while (0)
	NUM(0, INT64_MAX, r->sequence);
	STR(1, r->request.subject);
	STR(2, r->request.id);
	NUM(3, VAU_WRITE_PREPARE, r->phase);
	NUM(4, VAU_FS_INSTALL, r->request.operation);
	STR(5, r->request.path);
	STR(6, r->request.destination);
	NUM(7, 1, r->request.yes);
	NUM(8, 1, r->request.recursive);
	NUM(9, 1, r->request.overwrite);
	NUM(10, INT64_MAX, r->request.bytes);
	STR(11, r->request.sha256);
	STR(12, r->request.expected_sha256);

	char result[24];

	rc = column(s, 13, result, sizeof(result));
	if (rc)
		return rc;

	int negative  = result[0] == '-';
	const char *p = result + negative;

	value = 0;
	if (!*p)
		return VAU_DEVICE_ERROR;

	uint64_t max = negative ? (uint64_t)INT_MAX + 1 : INT_MAX;

	while (*p) {
		if (*p < '0' || *p > '9' || value > max / 10 ||
		    (value == max / 10 && (unsigned)(*p - '0') > max % 10)) {
			return VAU_DEVICE_ERROR;
		}

		value = value * 10 + (unsigned)(*p++ - '0');
	}

	r->result = negative ? (value == (uint64_t)INT_MAX + 1 ? INT_MIN : -(int)value) : (int)value;
	NUM(14, 1, r->effect_started);
	NUM(15, 1, r->readback_required);
	NUM(16, INT64_MAX, r->observed_us);
	NUM(17, INT64_MAX, r->offset);
	STR(18, r->detail);
	STR(19, r->request.trash_id);
	STR(20, r->detail_path);
	STR(21, r->effect_path);
	NUM(22, 11, r->before.state);
	NUM(23, INT64_MAX, r->before.bytes);
	NUM(24, 11, r->after.state);
	NUM(25, INT64_MAX, r->after.bytes);
	NUM(26, 11, r->destination_before.state);
	NUM(27, INT64_MAX, r->destination_before.bytes);
	NUM(28, 11, r->destination_after.state);
	NUM(29, INT64_MAX, r->destination_after.bytes);
#undef NUM
#undef STR
	return r->sequence && request_valid(&r->request) && r->result <= 0 &&
	                       observation_valid(&r->before) && observation_valid(&r->after) &&
	                       observation_valid(&r->destination_before) &&
	                       observation_valid(&r->destination_after)
	               ? VAU_OK
	               : VAU_DEVICE_ERROR;
}

int vau_journal_close(struct vau_write_journal *j)
{
	if (!j || !j->db)
		return VAU_INVALID;

	int rc = sqlite3_close(j->db);

	if (!rc)
		j->db = NULL;
	return error(rc);
}

int vau_journal_open(struct vau_write_journal *j, const char *path)
{
	if (!j || !path || j->db)
		return VAU_INVALID;
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return error(configured);

	configured = vau_sqlite_vfs_configure();
	if (configured)
		return error(configured);
#endif
	sqlite3 *db = NULL;

	int rc = error(sqlite3_open_v2(path, &db, 6,
#ifdef VAU_NATIVE_FORMAT
	                               VAU_JOURNAL_VFS
#else
	                               NULL
#endif
	                               )); /* READWRITE|CREATE */
	if (rc) {
		if (db)
			sqlite3_close(db);
#ifdef VAU_NATIVE_FORMAT
		int native = vau_sqlite_vfs_native_error();
		if (native)
			return native;
#endif
		return rc;
	}

	rc = exec(
	        db,
	        "PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;PRAGMA cache_size=32;PRAGMA temp_store=MEMORY");

	sqlite3_stmt *s = NULL;

	if (!rc)
		rc = prepare(db, "PRAGMA user_version", &s);

	uint64_t version = 0;

	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 100 ? integer(s, 0, 3, &version) : error(step);
	}

	if (s) {
		int closed = error(sqlite3_finalize(s));

		s = NULL;
		if (!rc)
			rc = closed;
	}

	if (!rc && !version) {
		rc = prepare(db, "SELECT count(*) FROM sqlite_master WHERE type='table'", &s);

		uint64_t count = 0;

		if (!rc) {
			int step = sqlite3_step(s);

			rc = step == 100 ? integer(s, 0, INT64_MAX, &count) : error(step);
		}

		if (s) {
			int closed = error(sqlite3_finalize(s));

			s = NULL;
			if (!rc)
				rc = closed;
		}

		if (!rc && count)
			rc = VAU_STALE; /* Never repurpose an unrelated database. */
		if (!rc) {
			rc = exec(
			        db,
			        "BEGIN IMMEDIATE;CREATE TABLE events("
			        "sequence INTEGER PRIMARY KEY AUTOINCREMENT,subject TEXT NOT NULL,operation_id TEXT NOT NULL,"
			        "phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 3),operation INTEGER NOT NULL,"
			        "path TEXT NOT NULL,destination TEXT NOT NULL,yes INTEGER NOT NULL,recursive INTEGER NOT NULL,"
			        "overwrite INTEGER NOT NULL,bytes TEXT NOT NULL,sha256 TEXT NOT NULL,expected_sha256 TEXT NOT NULL,"
			        "result INTEGER NOT NULL,effect_started INTEGER NOT NULL,readback_required INTEGER NOT NULL,"
			        "observed_us TEXT NOT NULL,offset TEXT NOT NULL,detail TEXT NOT NULL,trash_id TEXT NOT NULL,detail_path TEXT NOT NULL,effect_path TEXT NOT NULL,"
			        "before_state INTEGER NOT NULL,before_bytes TEXT NOT NULL,after_state INTEGER NOT NULL,after_bytes TEXT NOT NULL,"
			        "destination_before_state INTEGER NOT NULL,destination_before_bytes TEXT NOT NULL,destination_after_state INTEGER NOT NULL,destination_after_bytes TEXT NOT NULL);"
			        "CREATE INDEX operation_events ON events(subject,operation_id,phase,sequence);"
			        "PRAGMA user_version=3;COMMIT");
		}
	}

	if (!rc && version == 1) {
		rc = exec(
		        db,
		        "BEGIN IMMEDIATE;ALTER TABLE events ADD COLUMN trash_id TEXT NOT NULL DEFAULT '';"
		        "ALTER TABLE events ADD COLUMN detail_path TEXT NOT NULL DEFAULT '';PRAGMA user_version=2;COMMIT");
	}

	if (!rc && (version == 1 || version == 2)) {
		rc = exec(
		        db,
		        "BEGIN IMMEDIATE;"
		        "ALTER TABLE events ADD COLUMN effect_path TEXT NOT NULL DEFAULT '';"
		        "ALTER TABLE events ADD COLUMN before_state INTEGER NOT NULL DEFAULT 0;"
		        "ALTER TABLE events ADD COLUMN before_bytes TEXT NOT NULL DEFAULT '0';"
		        "ALTER TABLE events ADD COLUMN after_state INTEGER NOT NULL DEFAULT 0;"
		        "ALTER TABLE events ADD COLUMN after_bytes TEXT NOT NULL DEFAULT '0';"
		        "ALTER TABLE events ADD COLUMN destination_before_state INTEGER NOT NULL DEFAULT 0;"
		        "ALTER TABLE events ADD COLUMN destination_before_bytes TEXT NOT NULL DEFAULT '0';"
		        "ALTER TABLE events ADD COLUMN destination_after_state INTEGER NOT NULL DEFAULT 0;"
		        "ALTER TABLE events ADD COLUMN destination_after_bytes TEXT NOT NULL DEFAULT '0';"
		        "PRAGMA user_version=3;COMMIT");
	}

	/* Validate expected columns before declaring the journal usable. */
	if (!rc) {
		char sql[1536];
		int n = vau_snprintf(sql, sizeof(sql), "SELECT %s FROM events LIMIT 0", fields);

		rc = n > 0 && (size_t)n < sizeof(sql) ? prepare(db, sql, &s) : VAU_DEVICE_ERROR;
	}

	if (s) {
		int closed = error(sqlite3_finalize(s));

		if (!rc)
			rc = closed;
	}

	if (rc) {
		sqlite3_close(db);
		return rc;
	}

	j->db = db;
	return VAU_OK;
}

int vau_journal_open_readonly(struct vau_write_journal *j, const char *path)
{
	if (!j || !path || j->db)
		return VAU_INVALID;
#ifdef VAU_NATIVE_FORMAT
	int configured = vau_sqlite_memory_configure();
	if (configured)
		return error(configured);

	configured = vau_sqlite_vfs_configure();
	if (configured)
		return error(configured);
#endif
	sqlite3 *db = NULL;

	int rc = error(sqlite3_open_v2(path, &db, 1,
#ifdef VAU_NATIVE_FORMAT
	                               VAU_JOURNAL_VFS
#else
	                               NULL
#endif
	                               )); /* READONLY; never CREATE */
	if (rc) {
		if (db)
			sqlite3_close(db);
		return rc;
	}

	/* Keep observational/chunk lookups within the same bounded page cache
	 * as writable handles. These pragmas change connection-local state only. */
	rc = exec(db, "PRAGMA cache_size=32;PRAGMA temp_store=MEMORY");
	if (rc) {
		sqlite3_close(db);
		return rc;
	}

	sqlite3_stmt *s  = NULL;
	uint64_t version = 0;

	rc = prepare(db, "PRAGMA user_version", &s);
	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 100 ? integer(s, 0, 3, &version) : error(step);
	}

	if (s) {
		int closed = error(sqlite3_finalize(s));

		s = NULL;
		if (!rc)
			rc = closed;
	}

	if (!rc && version != 3)
		rc = VAU_STALE;
	if (!rc) {
		char sql[1536];
		int n = vau_snprintf(sql, sizeof(sql), "SELECT %s FROM events LIMIT 0", fields);

		rc = n > 0 && (size_t)n < sizeof(sql) ? prepare(db, sql, &s) : VAU_DEVICE_ERROR;
	}

	if (s) {
		int closed = error(sqlite3_finalize(s));

		if (!rc)
			rc = closed;
	}

	if (rc) {
		sqlite3_close(db);
		return rc;
	}

	j->db = db;
	return VAU_OK;
}

static int lookup(void *context, const char *subject, const char *id, struct vau_write_record *out,
                  int prepared)
{
	struct vau_write_journal *j = context;

	if (!j || !j->db || !subject || !id || !out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	char sql[1536];
	int n = vau_snprintf(
	        sql, sizeof(sql),
	        "SELECT %s FROM events WHERE subject=?1 AND operation_id=?2 AND phase IN(%s) ORDER BY sequence DESC LIMIT 1",
	        fields, prepared ? "0,1,3" : "0,1");

	if (n <= 0 || (size_t)n >= sizeof(sql))
		return VAU_DEVICE_ERROR;

	sqlite3_stmt *s = NULL;
	int rc          = prepare(j->db, sql, &s);

	if (!rc)
		rc = text(s, 1, subject);
	if (!rc)
		rc = text(s, 2, id);
	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 100 ? decode(s, out) : step == 101 ? 1 : error(step);
	}

	if (s) {
		int closed = error(sqlite3_finalize(s));

		if (rc >= 0 && closed)
			rc = closed;
	}

	return rc;
}

int vau_journal_lookup(void *context, const char *subject, const char *id,
                       struct vau_write_record *out)
{
	return lookup(context, subject, id, out, 0);
}

int vau_journal_state(void *context, const char *subject, const char *id,
                      struct vau_write_record *out)
{
	return lookup(context, subject, id, out, 1);
}

static int bounded(const char *p, size_t n)
{
	return memchr(p, 0, n) != NULL;
}

static int hex(const char *p, size_t n)
{
	for (size_t i = 0; i < n; ++i)
		if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f')))
			return 0;
	return !p[n];
}

static int request_valid(const struct vau_write_request *r)
{
	char path[VAU_PATH_MAX];

	if (!hex(r->subject, 64) || !hex(r->id, 32) ||
	    (r->operation == VAU_FS_PURGE ? !hex(r->trash_id, 32) || !strcmp(r->trash_id, r->id)
	                                  : !!*r->trash_id) ||
	    vau_path_normalize(r->path, path, sizeof(path)) || strcmp(path, r->path) ||
	    r->operation == VAU_FS_READ || r->operation == VAU_FS_RENAME_DESTINATION ||
	    (unsigned)r->operation > VAU_FS_INSTALL || r->yes > 1 || r->recursive > 1 ||
	    r->overwrite > 1 || r->bytes > INT64_MAX) {
		return 0;
	}

	if (r->operation == VAU_FS_RENAME_SOURCE) {
		if (vau_path_normalize(r->destination, path, sizeof(path)) || strcmp(path, r->destination))
			return 0;
	} else if (*r->destination) {
		return 0;
	}

	if (r->operation == VAU_FS_INSTALL) {
		size_t length = strlen(r->path);

		return r->yes && !r->recursive && !r->overwrite && r->bytes >= 22 && !*r->sha256 &&
		       !*r->expected_sha256 && length >= 5 && !strcmp(r->path + length - 4, ".vpk");
	}

	if (r->operation == VAU_FS_WRITE) {
		return !r->recursive && hex(r->sha256, 64) &&
		       (r->overwrite ? (!*r->expected_sha256 || hex(r->expected_sha256, 64))
		                     : !*r->expected_sha256);
	}

	return !r->overwrite && !r->bytes && !*r->sha256 && !*r->expected_sha256;
}

int vau_journal_append(void *context, struct vau_write_record *r)
{
	struct vau_write_journal *j = context;

	if (!j || !j->db || !r || (unsigned)r->phase > VAU_WRITE_PREPARE ||
	    !bounded(r->request.subject, sizeof(r->request.subject)) ||
	    !bounded(r->request.id, sizeof(r->request.id)) ||
	    !bounded(r->request.path, sizeof(r->request.path)) ||
	    !bounded(r->request.destination, sizeof(r->request.destination)) ||
	    !bounded(r->request.sha256, sizeof(r->request.sha256)) ||
	    !bounded(r->request.expected_sha256, sizeof(r->request.expected_sha256)) ||
	    !bounded(r->request.trash_id, sizeof(r->request.trash_id)) ||
	    !bounded(r->detail_path, sizeof(r->detail_path)) ||
	    !bounded(r->effect_path, sizeof(r->effect_path)) ||
	    !bounded(r->detail, sizeof(r->detail)) || r->effect_started > 1 ||
	    r->readback_required > 1 || r->observed_us > INT64_MAX || r->offset > INT64_MAX) {
		return VAU_INVALID;
	}

	if (!request_valid(&r->request) || r->result > 0 || !observation_valid(&r->before) ||
	    !observation_valid(&r->after) || !observation_valid(&r->destination_before) ||
	    !observation_valid(&r->destination_after) ||
	    (r->phase == VAU_WRITE_PREPARE && r->request.operation != VAU_FS_WRITE) ||
	    (r->phase == VAU_WRITE_PROGRESS && !*r->detail)) {
		return VAU_INVALID;
	}

	int rc = exec(j->db, "BEGIN IMMEDIATE");

	if (rc)
		return rc;

	struct vau_write_record existing;

	rc = vau_journal_state(j, r->request.subject, r->request.id, &existing);
	if (rc == 1) {
		rc = (r->phase == VAU_WRITE_INTENT || r->phase == VAU_WRITE_PREPARE) ? VAU_OK : VAU_STALE;
	} else if (!rc) {
		if (!vau_write_request_same(&existing.request, &r->request) ||
		    existing.phase == VAU_WRITE_COMPLETE || r->phase == VAU_WRITE_PREPARE ||
		    (r->phase == VAU_WRITE_INTENT && existing.phase != VAU_WRITE_PREPARE) ||
		    (r->phase == VAU_WRITE_COMPLETE && existing.phase != VAU_WRITE_INTENT)) {
			rc = VAU_STALE;
		}
	}

	sqlite3_stmt *s = NULL;

	if (!rc) {
		rc = prepare(
		        j->db,
		        "INSERT INTO events(subject,operation_id,phase,operation,path,destination,yes,recursive,overwrite,bytes,sha256,expected_sha256,result,effect_started,readback_required,observed_us,offset,detail,trash_id,detail_path,effect_path,before_state,before_bytes,after_state,after_bytes,destination_before_state,destination_before_bytes,destination_after_state,destination_after_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29)",
		        &s);
	}

	char numbers[19][24];
	unsigned at = 0;
#define TEXT(i, v)              \
	do {                        \
		if (!rc)                \
			rc = text(s, i, v); \
	} while (0)
#define NUMBER(i, v)                             \
	do {                                         \
		if (!rc)                                 \
			rc = number(s, i, v, numbers[at++]); \
	} while (0)
	TEXT(1, r->request.subject);
	TEXT(2, r->request.id);
	NUMBER(3, r->phase);
	NUMBER(4, r->request.operation);
	TEXT(5, r->request.path);
	TEXT(6, r->request.destination);
	NUMBER(7, r->request.yes);
	NUMBER(8, r->request.recursive);
	NUMBER(9, r->request.overwrite);
	NUMBER(10, r->request.bytes);
	TEXT(11, r->request.sha256);
	TEXT(12, r->request.expected_sha256);

	int n = vau_snprintf(numbers[at], 24, "%d", r->result);

	if (!rc)
		rc = n > 0 && n < 24 ? text(s, 13, numbers[at++]) : VAU_DEVICE_ERROR;
	NUMBER(14, r->effect_started);
	NUMBER(15, r->readback_required);
	NUMBER(16, r->observed_us);
	NUMBER(17, r->offset);
	TEXT(18, r->detail);
	TEXT(19, r->request.trash_id);
	TEXT(20, r->detail_path);
	TEXT(21, r->effect_path);
	NUMBER(22, r->before.state);
	NUMBER(23, r->before.bytes);
	NUMBER(24, r->after.state);
	NUMBER(25, r->after.bytes);
	NUMBER(26, r->destination_before.state);
	NUMBER(27, r->destination_before.bytes);
	NUMBER(28, r->destination_after.state);
	NUMBER(29, r->destination_after.bytes);
#undef TEXT
#undef NUMBER
	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 101 ? VAU_OK : error(step);
	}

	if (s) {
		int closed = error(sqlite3_finalize(s));

		s = NULL;
		if (!rc)
			rc = closed;
	}

	uint64_t sequence = 0;

	if (!rc)
		rc = prepare(j->db, "SELECT last_insert_rowid()", &s);
	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 100 ? integer(s, 0, INT64_MAX, &sequence) : error(step);
	}

	if (s) {
		int closed = error(sqlite3_finalize(s));

		if (!rc)
			rc = closed;
	}

	if (!rc)
		rc = exec(j->db, "COMMIT");
	if (rc)
		(void)exec(j->db, "ROLLBACK");
	else
		r->sequence = sequence;
	return rc;
}

int vau_journal_page(struct vau_write_journal *j, uint64_t after, int pending,
                     struct vau_audit_page *out)
{
	if (!j || !j->db || !out || after > INT64_MAX || (pending != 0 && pending != 1))
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	out->next_sequence = after;

	char sql[1536], value[24];
	int n = vau_snprintf(
	        sql, sizeof(sql),
	        "SELECT %s FROM events WHERE sequence>?1 %s ORDER BY sequence LIMIT 3", fields,
	        pending ? "AND phase IN(0,3) AND NOT EXISTS(SELECT 1 FROM events done WHERE done.subject=events.subject AND done.operation_id=events.operation_id AND (done.phase=1 OR (events.phase=3 AND done.phase=0)))"
	                : "");

	if (n <= 0 || (size_t)n >= sizeof(sql))
		return VAU_DEVICE_ERROR;

	sqlite3_stmt *s = NULL;
	int rc          = prepare(j->db, sql, &s);

	if (!rc)
		rc = number(s, 1, after, value);
	while (!rc) {
		int step = sqlite3_step(s);

		if (step == 101)
			break;
		if (step != 100) {
			rc = error(step);
			break;
		}

		if (out->count == VAU_AUDIT_PAGE_ENTRIES) {
			out->more = 1;
			break;
		}

		struct vau_write_record *r = &out->records[out->count];

		rc = decode(s, r);
		if (rc)
			break;
		if (r->sequence <= out->next_sequence) {
			rc = VAU_DEVICE_ERROR;
			break;
		}

		out->next_sequence = r->sequence;
		++out->count;
	}

	if (s) {
		int closed = error(sqlite3_finalize(s));

		if (!rc)
			rc = closed;
	}

	if (rc)
		memset(out, 0, sizeof(*out));
	return rc;
}
