/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_scope.h"
#include "format.h"
#include <limits.h>
#include <string.h>

/* Raw SQLite result codes and the -65536 error encoding: see sqlite_api.h. */

static int scope_error(int rc)
{
	return rc ? -65536 - rc : 0;
}

static int scope_prepare(sqlite3 *db, const char *sql, sqlite3_stmt **s)
{
	return scope_error(sqlite3_prepare_v2(db, sql, -1, s, NULL));
}

static int scope_finish(sqlite3_stmt *s, int rc)
{
	if (s) {
		int end = scope_error(sqlite3_finalize(s));

		if (!rc)
			rc = end;
	}

	return rc;
}

static int scope_done(sqlite3_stmt *s)
{
	int rc = sqlite3_step(s);

	return rc == 101 ? 0 : scope_error(rc);
}

static int scope_bind(sqlite3_stmt *s, int index, const char *value)
{
	return scope_error(sqlite3_bind_text(s, index, value, -1, NULL));
}

static int scope_text(sqlite3_stmt *s, int index, char *out, size_t cap)
{
	const unsigned char *p = sqlite3_column_text(s, index);
	int n                  = sqlite3_column_bytes(s, index);

	if (!p || n < 0 || (size_t)n >= cap || memchr(p, 0, (size_t)n))
		return VAU_DEVICE_ERROR;

	memcpy(out, p, (size_t)n);
	out[n] = 0;
	return 0;
}

static int scope_decimal(const char *p, uint64_t max, uint64_t *out)
{
	if (!*p)
		return VAU_DEVICE_ERROR;

	uint64_t value = 0;

	for (; *p; p++) {
		if (*p < '0' || *p > '9' || value > max / 10 ||
		    (value == max / 10 && (unsigned)(*p - '0') > max % 10)) {
			return VAU_DEVICE_ERROR;
		}

		value = value * 10 + (unsigned)(*p - '0');
	}

	*out = value;
	return 0;
}

static int scope_number(sqlite3_stmt *s, int index, uint64_t max, uint64_t *out)
{
	char buffer[24];
	int rc = scope_text(s, index, buffer, sizeof(buffer));

	return rc ? rc : scope_decimal(buffer, max, out);
}

static int scope_signed_number(sqlite3_stmt *s, int index, int *out)
{
	char buffer[24];
	int rc = scope_text(s, index, buffer, sizeof(buffer));

	if (rc)
		return rc;

	const char *p = buffer;
	int negative  = *p == '-';

	if (negative)
		p++;

	uint64_t value;

	rc = scope_decimal(p, negative ? (uint64_t)INT_MAX + 1 : INT_MAX, &value);
	if (rc)
		return rc;

	*out = negative ? value == (uint64_t)INT_MAX + 1 ? INT_MIN : -(int)value : (int)value;
	return 0;
}

static int scope_modified(const struct vau_file_info *i, char out[32])
{
	int n = vau_snprintf(out, 32, "%04u-%02u-%02uT%02u:%02u:%02u.%06u", i->year, i->month, i->day,
	                     i->hour, i->minute, i->second, i->microsecond);

	return n == 26 ? 0 : VAU_INVALID;
}

static int scope_date(const char *s, struct vau_file_info *out)
{
	if (strlen(s) != 26 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
	    s[16] != ':' || s[19] != '.') {
		return VAU_DEVICE_ERROR;
	}

	const unsigned start[] = { 0, 5, 8, 11, 14, 17, 20 }, length[] = { 4, 2, 2, 2, 2, 2, 6 };
	unsigned values[7] = { 0 };

	for (unsigned i = 0; i < 7; i++) {
		for (unsigned j = 0; j < length[i]; j++) {
			char c = s[start[i] + j];

			if (c < '0' || c > '9')
				return VAU_DEVICE_ERROR;

			values[i] = values[i] * 10 + (unsigned)(c - '0');
		}
	}

	out->year        = values[0];
	out->month       = values[1];
	out->day         = values[2];
	out->hour        = values[3];
	out->minute      = values[4];
	out->second      = values[5];
	out->microsecond = values[6];
	return 0;
}

static int scope_decode_scope(sqlite3_stmt *s, struct vau_content_scope *out)
{
	memset(out, 0, sizeof(*out));

	uint64_t n;
	int rc;

	if ((rc = scope_number(s, 0, INT64_MAX, &out->sequence)) || !out->sequence)
		return rc ? rc : VAU_DEVICE_ERROR;
	if ((rc = scope_text(s, 1, out->request.subject, sizeof(out->request.subject))) ||
	    (rc = scope_text(s, 2, out->request.id, sizeof(out->request.id))) ||
	    (rc = scope_text(s, 3, out->request.title, sizeof(out->request.title)))) {
		return rc;
	}

	out->request.yes = 1;
	if ((rc = scope_number(s, 4, VAU_CONTENT_SCOPE_AFTER, &n)))
		return rc;

	out->phase = n;
	if ((rc = scope_number(s, 5, INT64_MAX, &out->observed_us)) ||
	    (rc = scope_number(s, 6, INT64_MAX, &out->path_count))) {
		return rc;
	}

	if ((rc = scope_number(s, 7, VAU_CONTENT_VIDEO, &n)))
		return rc;

	out->request.kind = n;
	if ((rc = scope_number(s, 8, 63, &n)))
		return rc;

	out->request.user = n;
	if ((rc = scope_number(s, 9, INT64_MAX, &out->request.media_id)))
		return rc;
	return vau_content_delete_request_valid(&out->request) && out->path_count ? 0
	                                                                          : VAU_DEVICE_ERROR;
}

static int scope_decode_path(sqlite3_stmt *s, struct vau_content_scope_path *out)
{
	memset(out, 0, sizeof(*out));

	uint64_t n;
	int rc;

	if ((rc = scope_number(s, 0, INT64_MAX, &out->sequence)) || !out->sequence)
		return rc ? rc : VAU_DEVICE_ERROR;
	if ((rc = scope_text(s, 1, out->path, sizeof(out->path))))
		return rc;

	char normalized[VAU_PATH_MAX];

	if (vau_path_normalize(out->path, normalized, sizeof(normalized)) ||
	    strcmp(out->path, normalized)) {
		return VAU_DEVICE_ERROR;
	}

	if ((rc = scope_number(s, 2, VAU_CONTENT_MEDIA_TEMP, &n)))
		return rc;

	out->role = n;
	if ((rc = scope_number(s, 3, 1, &n)))
		return rc;

	out->root = n;
	if ((rc = scope_number(s, 4, VAU_STATE_DIRECTORY, &n)))
		return rc;

	out->observation.state = n;
	if ((rc = scope_signed_number(s, 5, &out->observation.error)) ||
	    (rc = scope_number(s, 6, UINT64_MAX, &out->observation.info.bytes))) {
		return rc;
	}

	if ((rc = scope_number(s, 7, UINT32_MAX, &n)))
		return rc;

	out->observation.info.mode = n;
	if ((rc = scope_number(s, 8, UINT32_MAX, &n)))
		return rc;

	out->observation.info.attributes = n;

	char time[32];

	if ((rc = scope_text(s, 9, time, sizeof(time))) ||
	    (rc = scope_date(time, &out->observation.info))) {
		return rc;
	}

	out->observation.info.kind = out->observation.state == VAU_STATE_FILE ? VAU_FILE_REGULAR
	                             : out->observation.state == VAU_STATE_DIRECTORY
	                                     ? VAU_FILE_DIRECTORY
	                                     : VAU_FILE_OTHER;
	return vau_content_path_observation_valid(&out->observation) ? 0 : VAU_DEVICE_ERROR;
}

static int scope_active(const struct vau_content_scope_writer *w)
{
	return w && w->journal && w->journal->db && w->scope.sequence &&
	       w->journal->scope_active == w->scope.sequence;
}

static int scope_fail(struct vau_content_scope_writer *w, int rc)
{
	if (rc && !w->failure)
		w->failure = rc;
	return rc;
}

int vau_content_scope_abort(struct vau_content_scope_writer *w)
{
	if (!scope_active(w))
		return VAU_INVALID;

	int rc = scope_error(sqlite3_exec(w->journal->db, "ROLLBACK", NULL, NULL, NULL));

	if (!rc) {
		w->journal->scope_active = 0;
		memset(w, 0, sizeof(*w));
	}

	return rc;
}

int vau_content_scope_begin(struct vau_content_scope_writer *w, struct vau_content_journal *j,
                            const struct vau_content_delete_request *request,
                            enum vau_content_scope_phase phase, uint64_t now)
{
	if (!w || !j || !j->db || !vau_content_delete_request_valid(request) ||
	    (unsigned)phase > VAU_CONTENT_SCOPE_AFTER || now > INT64_MAX) {
		return VAU_INVALID;
	}

	if (j->scope_active || w->journal)
		return VAU_BUSY;

	struct vau_content_delete_record operation;
	int existing = vau_content_journal_lookup(j, request->subject, request->id, &operation);

	if (existing < 0)
		return existing;
	if (!existing && !vau_content_delete_target_same(&operation.request, request))
		return VAU_STALE;

	sqlite3_stmt *identity = NULL;
	int identity_rc        = scope_prepare(j->db,
	                                       "SELECT title,operation_kind,target_user,media_id FROM "
	                                              "content_scopes WHERE "
	                                              "subject=?1 AND operation_id=?2 LIMIT 1",
	                                       &identity);

	if (!identity_rc)
		identity_rc = scope_bind(identity, 1, request->subject);
	if (!identity_rc)
		identity_rc = scope_bind(identity, 2, request->id);
	if (!identity_rc) {
		int step = sqlite3_step(identity);

		if (step == 100) {
			char title[10];

			identity_rc = scope_text(identity, 0, title, sizeof(title));
			if (!identity_rc && strcmp(title, request->title))
				identity_rc = VAU_STALE;

			uint64_t operation_kind, target_user, media_id;

			if (!identity_rc)
				identity_rc = scope_number(identity, 1, VAU_CONTENT_VIDEO, &operation_kind);
			if (!identity_rc)
				identity_rc = scope_number(identity, 2, 63, &target_user);
			if (!identity_rc)
				identity_rc = scope_number(identity, 3, INT64_MAX, &media_id);
			if (!identity_rc && (operation_kind != request->kind || target_user != request->user ||
			                     media_id != request->media_id)) {
				identity_rc = VAU_STALE;
			}
		} else if (step != 101) {
			identity_rc = scope_error(step);
		}
	}

	identity_rc = scope_finish(identity, identity_rc);
	if (identity_rc)
		return identity_rc;

	memset(w, 0, sizeof(*w));

	int rc = scope_error(sqlite3_exec(j->db, "BEGIN IMMEDIATE", NULL, NULL, NULL));

	if (rc)
		return rc;

	sqlite3_stmt *s = NULL;
	char when[24], kind[12], operation_kind[12], target_user[12], media_id[24];

	vau_snprintf(when, sizeof(when), "%llu", (unsigned long long)now);
	vau_snprintf(kind, sizeof(kind), "%u", phase);
	vau_snprintf(operation_kind, sizeof(operation_kind), "%u", request->kind);
	vau_snprintf(target_user, sizeof(target_user), "%u", request->user);
	vau_snprintf(media_id, sizeof(media_id), "%llu", (unsigned long long)request->media_id);
	rc = scope_prepare(j->db,
	                   "INSERT INTO "
	                   "content_scopes(subject,operation_id,title,phase,observed_"
	                   "us,operation_kind,target_user,"
	                   "media_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
	                   &s);
	if (!rc)
		rc = scope_bind(s, 1, request->subject);
	if (!rc)
		rc = scope_bind(s, 2, request->id);
	if (!rc)
		rc = scope_bind(s, 3, request->title);
	if (!rc)
		rc = scope_bind(s, 4, kind);
	if (!rc)
		rc = scope_bind(s, 5, when);
	if (!rc)
		rc = scope_bind(s, 6, operation_kind);
	if (!rc)
		rc = scope_bind(s, 7, target_user);
	if (!rc)
		rc = scope_bind(s, 8, media_id);
	if (!rc)
		rc = scope_done(s);
	rc = scope_finish(s, rc);
	s  = NULL;

	uint64_t sequence = 0;

	if (!rc)
		rc = scope_prepare(j->db, "SELECT last_insert_rowid()", &s);
	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 100 ? scope_number(s, 0, INT64_MAX, &sequence) : scope_error(step);
	}

	rc = scope_finish(s, rc);
	if (!rc && !sequence)
		rc = VAU_DEVICE_ERROR;
	if (rc) {
		(void)sqlite3_exec(j->db, "ROLLBACK", NULL, NULL, NULL);
		return rc;
	}

	memset(w, 0, sizeof(*w));
	w->journal = j;
	w->scope   = (struct vau_content_scope){
		  .sequence = sequence, .request = *request, .phase = phase, .observed_us = now
	};
	j->scope_active = sequence;
	return 0;
}

int vau_content_scope_add(struct vau_content_scope_writer *w, const char *path,
                          enum vau_content_path_role role, unsigned root,
                          const struct vau_content_path_observation *observation)
{
	if (!scope_active(w))
		return VAU_INVALID;
	if (w->failure)
		return w->failure;
	if (!path || !vau_content_path_role_name(role) || root > 1 ||
	    !vau_content_path_observation_valid(observation)) {
		return scope_fail(w, VAU_INVALID);
	}

	if (w->scope.phase == VAU_CONTENT_SCOPE_BEFORE && observation->state == VAU_STATE_UNKNOWN)
		return scope_fail(w, observation->error);

	char normalized[VAU_PATH_MAX];

	if (vau_path_normalize(path, normalized, sizeof(normalized)) || strcmp(path, normalized))
		return scope_fail(w, VAU_INVALID);

	char values[8][32], stamp[32];
	uint64_t fields[] = {
		w->scope.sequence,
		(unsigned)role,
		root,
		observation->state,
		observation->info.bytes,
		observation->info.mode,
		observation->info.attributes,
	};

	for (unsigned i = 0; i < 7; i++)
		vau_snprintf(values[i], 32, "%llu", (unsigned long long)fields[i]);
	vau_snprintf(values[7], 32, "%d", observation->error);

	int rc = scope_modified(&observation->info, stamp);

	if (rc)
		return scope_fail(w, rc);

	sqlite3_stmt *s = NULL;

	/* Repeated roots (shared add-on IDs, root followed by a tree walk) must
	 * describe the same observation. A changed duplicate is a scan race. */
	rc = scope_prepare(w->journal->db,
	                   "SELECT "
	                   "sequence,path,role,is_root,state,error,bytes,mode,"
	                   "attributes,modified FROM "
	                   "content_scope_paths WHERE scope_sequence=CAST(?1 AS "
	                   "INTEGER) AND path=?2",
	                   &s);
	if (!rc)
		rc = scope_bind(s, 1, values[0]);
	if (!rc)
		rc = scope_bind(s, 2, path);

	int found = 0;

	if (!rc) {
		int step = sqlite3_step(s);

		if (step == 100) {
			struct vau_content_scope_path old;

			rc = scope_decode_path(s, &old);
			if (!rc) {
				char oldstamp[32];

				rc = scope_modified(&old.observation.info, oldstamp);
				if (!rc && (old.role != role || old.root < root ||
				            old.observation.state != observation->state ||
				            old.observation.error != observation->error ||
				            old.observation.info.bytes != observation->info.bytes ||
				            old.observation.info.mode != observation->info.mode ||
				            old.observation.info.attributes != observation->info.attributes ||
				            strcmp(oldstamp, stamp))) {
					rc = VAU_STALE;
				}
			}

			found = 1;
		} else if (step != 101) {
			rc = scope_error(step);
		}
	}

	rc = scope_finish(s, rc);
	s  = NULL;
	if (rc || found)
		return scope_fail(w, rc);
	if (w->scope.path_count >= INT64_MAX || (root && w->roots >= INT64_MAX))
		return scope_fail(w, VAU_INVALID);

	rc = scope_prepare(w->journal->db,
	                   "INSERT INTO "
	                   "content_scope_paths(scope_sequence,path,role,is_root,"
	                   "state,error,bytes,mode,attributes,"
	                   "modified) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
	                   &s);
	if (!rc)
		rc = scope_bind(s, 1, values[0]);
	if (!rc)
		rc = scope_bind(s, 2, path);
	if (!rc)
		rc = scope_bind(s, 3, values[1]);
	if (!rc)
		rc = scope_bind(s, 4, values[2]);
	if (!rc)
		rc = scope_bind(s, 5, values[3]);
	if (!rc)
		rc = scope_bind(s, 6, values[7]);
	if (!rc)
		rc = scope_bind(s, 7, values[4]);
	if (!rc)
		rc = scope_bind(s, 8, values[5]);
	if (!rc)
		rc = scope_bind(s, 9, values[6]);
	if (!rc)
		rc = scope_bind(s, 10, stamp);
	if (!rc)
		rc = scope_done(s);
	rc = scope_finish(s, rc);
	if (!rc) {
		w->scope.path_count++;
		if (root)
			w->roots++;
	}

	return scope_fail(w, rc);
}

int vau_content_scope_commit(struct vau_content_scope_writer *w)
{
	if (!scope_active(w))
		return VAU_INVALID;
	if (w->failure)
		return w->failure;
	if (w->scope.request.kind >= VAU_CONTENT_PHOTO && !w->media_added)
		return VAU_INVALID;
	if (w->albums_started && !w->albums_finished)
		return VAU_INVALID;
	if (!w->scope.path_count || !w->roots)
		return VAU_INVALID;

	char id[24], count[24];

	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)w->scope.sequence);
	vau_snprintf(count, sizeof(count), "%llu", (unsigned long long)w->scope.path_count);

	sqlite3_stmt *s = NULL;
	int rc          = scope_prepare(w->journal->db,
	                                "UPDATE content_scopes SET path_count=CAST(?1 AS "
	                                         "INTEGER) WHERE sequence=CAST(?2 AS INTEGER)",
	                                &s);

	if (!rc)
		rc = scope_bind(s, 1, count);
	if (!rc)
		rc = scope_bind(s, 2, id);
	if (!rc)
		rc = scope_done(s);
	rc = scope_finish(s, rc);
	if (!rc)
		rc = scope_error(sqlite3_exec(w->journal->db, "COMMIT", NULL, NULL, NULL));
	if (!rc) {
		w->journal->scope_active = 0;
		w->journal               = NULL;
	}

	return rc;
}

int vau_content_scope_latest(struct vau_content_journal *j,
                             const struct vau_content_delete_request *request,
                             enum vau_content_scope_phase phase, struct vau_content_scope *out)
{
	if (!j || !j->db || !out || !vau_content_delete_request_valid(request) ||
	    (unsigned)phase > VAU_CONTENT_SCOPE_AFTER) {
		return VAU_INVALID;
	}

	if (j->scope_active)
		return VAU_BUSY;

	sqlite3_stmt *s = NULL;
	char kind[12];

	vau_snprintf(kind, sizeof(kind), "%u", phase);

	int rc = scope_prepare(j->db,
	                       "SELECT "
	                       "sequence,subject,operation_id,title,phase,observed_"
	                       "us,path_count,operation_kind,target_user,"
	                       "media_id FROM content_scopes WHERE "
	                       "subject=?1 AND operation_id=?2 AND phase=CAST(?3 AS "
	                       "INTEGER) ORDER BY sequence DESC LIMIT 1",
	                       &s);

	if (!rc)
		rc = scope_bind(s, 1, request->subject);
	if (!rc)
		rc = scope_bind(s, 2, request->id);
	if (!rc)
		rc = scope_bind(s, 3, kind);

	struct vau_content_scope found = { 0 };

	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 101 ? 1 : step == 100 ? scope_decode_scope(s, &found) : scope_error(step);
	}

	if (!rc && !vau_content_delete_target_same(&found.request, request))
		rc = VAU_STALE;
	rc = scope_finish(s, rc);
	if (!rc)
		*out = found;
	return rc;
}

static int scope_page_read(struct vau_content_journal *j, uint64_t scope, uint64_t after,
                           struct vau_content_scope_page *out,
                           const struct vau_content_scope_writer *owner)
{
	if (!j || !j->db || !out || !scope || scope > INT64_MAX || after > INT64_MAX)
		return VAU_INVALID;
	if (j->scope_active &&
	    (!scope_active(owner) || owner->journal != j ||
	     owner->scope.phase != VAU_CONTENT_SCOPE_AFTER || scope == owner->scope.sequence)) {
		return VAU_BUSY;
	}

	memset(out, 0, sizeof(*out));
	out->next = after;

	char id[24], cursor[24];

	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)scope);
	vau_snprintf(cursor, sizeof(cursor), "%llu", (unsigned long long)after);

	sqlite3_stmt *s = NULL;
	int rc          = scope_prepare(j->db,
	                                "SELECT "
	                                         "sequence,subject,operation_id,title,phase,observed_"
	                                         "us,path_count,operation_kind,target_"
	                                         "user,media_id FROM "
	                                         "content_scopes WHERE sequence=CAST(?1 AS INTEGER)",
	                                &s);

	if (!rc)
		rc = scope_bind(s, 1, id);
	if (!rc) {
		int step = sqlite3_step(s);
		struct vau_content_scope header;

		rc = step == 101   ? VAU_STALE
		     : step == 100 ? scope_decode_scope(s, &header)
		                   : scope_error(step);
		if (!rc && owner &&
		    (header.phase != VAU_CONTENT_SCOPE_BEFORE ||
		     !vau_content_delete_target_same(&header.request, &owner->scope.request))) {
			rc = VAU_STALE;
		}
	}

	rc = scope_finish(s, rc);
	s  = NULL;
	if (rc)
		return rc;

	rc = scope_prepare(j->db,
	                   "SELECT "
	                   "sequence,path,role,is_root,state,error,bytes,mode,"
	                   "attributes,modified FROM "
	                   "content_scope_paths WHERE scope_sequence=CAST(?1 AS "
	                   "INTEGER) AND sequence>CAST(?2 AS "
	                   "INTEGER) ORDER BY sequence LIMIT 3",
	                   &s);
	if (!rc)
		rc = scope_bind(s, 1, id);
	if (!rc)
		rc = scope_bind(s, 2, cursor);
	if (!rc) {
		for (;;) {
			int step = sqlite3_step(s);

			if (step == 101)
				break;
			if (step != 100) {
				rc = scope_error(step);
				break;
			}

			if (out->count == 2) {
				out->more = 1;
				break;
			}

			struct vau_content_scope_path *entry = &out->entries[out->count];

			rc = scope_decode_path(s, entry);
			if (rc)
				break;
			if (entry->sequence <= out->next) {
				rc = VAU_STALE;
				break;
			}

			out->next = entry->sequence;
			out->count++;
		}
	}

	return scope_finish(s, rc);
}

int vau_content_scope_page(struct vau_content_journal *j, uint64_t scope, uint64_t after,
                           struct vau_content_scope_page *out)
{
	return scope_page_read(j, scope, after, out, NULL);
}

int vau_content_scope_source_page(struct vau_content_scope_writer *w, uint64_t scope,
                                  uint64_t after, struct vau_content_scope_page *out)
{
	if (!scope_active(w) || w->scope.phase != VAU_CONTENT_SCOPE_AFTER || w->failure)
		return VAU_INVALID;
	return scope_page_read(w->journal, scope, after, out, w);
}

static int scope_scope_read(struct vau_content_journal *j, uint64_t scope,
                            struct vau_content_scope *out,
                            const struct vau_content_scope_writer *owner)
{
	if (!j || !j->db || !out || !scope || scope > INT64_MAX)
		return VAU_INVALID;
	if (j->scope_active && (!owner || !scope_active(owner) || owner->journal != j ||
	                        owner->scope.phase != VAU_CONTENT_SCOPE_AFTER || owner->failure)) {
		return VAU_BUSY;
	}

	char id[24];

	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)scope);

	sqlite3_stmt *s = NULL;
	int rc          = scope_prepare(j->db,
	                                "SELECT "
	                                         "sequence,subject,operation_id,title,phase,observed_us,"
	                                         "path_count,operation_kind,target_"
	                                         "user,media_id "
	                                         "FROM content_scopes WHERE sequence=CAST(?1 AS INTEGER)",
	                                &s);

	if (!rc)
		rc = scope_bind(s, 1, id);

	struct vau_content_scope found = { 0 };

	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 101 ? 1 : step == 100 ? scope_decode_scope(s, &found) : scope_error(step);
	}

	rc = scope_finish(s, rc);
	if (!rc && owner &&
	    (found.phase != VAU_CONTENT_SCOPE_BEFORE ||
	     !vau_content_delete_target_same(&found.request, &owner->scope.request))) {
		rc = VAU_STALE;
	}

	if (!rc)
		*out = found;
	return rc;
}

int vau_content_scope_get(struct vau_content_journal *j, uint64_t scope,
                          struct vau_content_scope *out)
{
	return scope_scope_read(j, scope, out, NULL);
}

int vau_content_scope_find(struct vau_content_journal *j, uint64_t scope, const char *path,
                           struct vau_content_scope_path *out)
{
	if (!j || !j->db || !out || !path || !scope || scope > INT64_MAX)
		return VAU_INVALID;
	if (j->scope_active)
		return VAU_BUSY;

	char normalized[VAU_PATH_MAX], id[24];

	if (vau_path_normalize(path, normalized, sizeof(normalized)) || strcmp(path, normalized))
		return VAU_INVALID;

	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)scope);

	sqlite3_stmt *s = NULL;
	int rc          = scope_prepare(j->db,
	                                "SELECT "
	                                         "sequence,path,role,is_root,state,error,bytes,mode,attributes,modified "
	                                         "FROM content_scope_paths WHERE scope_sequence=CAST(?1 AS INTEGER) AND "
	                                         "path=?2",
	                                &s);

	if (!rc)
		rc = scope_bind(s, 1, id);
	if (!rc)
		rc = scope_bind(s, 2, path);

	struct vau_content_scope_path found;

	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 101 ? 1 : step == 100 ? scope_decode_path(s, &found) : scope_error(step);
	}

	rc = scope_finish(s, rc);
	if (!rc)
		*out = found;
	return rc;
}

static int scope_savedata_gone(const struct vau_content_scope_path *p)
{
	if (p->observation.state == VAU_STATE_UNKNOWN)
		return p->observation.error;
	if (p->role != VAU_CONTENT_SAVEDATA && p->role != VAU_CONTENT_STAGING)
		return VAU_STALE;
	if (p->role == VAU_CONTENT_STAGING && p->root && !strcmp(p->path, "ux0:temp/game")) {
		return p->observation.state == VAU_STATE_MISSING ||
		                       p->observation.state == VAU_STATE_DIRECTORY
		               ? 0
		               : VAU_STALE;
	}

	return p->observation.state == VAU_STATE_MISSING ? 0 : VAU_STALE;
}

int vau_content_scope_savedata_complete(struct vau_content_journal *j, uint64_t before,
                                        uint64_t after)
{
	struct vau_content_scope b, a;
	int rc = vau_content_scope_get(j, before, &b);

	if (rc)
		return rc == 1 ? VAU_STALE : rc;

	rc = vau_content_scope_get(j, after, &a);
	if (rc)
		return rc == 1 ? VAU_STALE : rc;
	if (b.request.kind != VAU_CONTENT_VITA_SAVEDATA || b.phase != VAU_CONTENT_SCOPE_BEFORE ||
	    a.phase != VAU_CONTENT_SCOPE_AFTER || after <= before ||
	    !vau_content_delete_target_same(&b.request, &a.request)) {
		return VAU_STALE;
	}

	struct vau_content_scope_page page;
	uint64_t cursor = 0, seen_before = 0, seen_after = 0;
	unsigned live = 0, staging = 0;
	char prefix[64];

	vau_snprintf(prefix, sizeof(prefix), "ux0:user/%02u/savedata/", b.request.user);
	do {
		rc = vau_content_scope_page(j, before, cursor, &page);
		if (rc)
			return rc;

		for (unsigned i = 0; i < page.count; i++) {
			++seen_before;

			const struct vau_content_scope_path *p = &page.entries[i];

			if (p->observation.state == VAU_STATE_UNKNOWN)
				return p->observation.error;
			if (p->role != VAU_CONTENT_SAVEDATA && p->role != VAU_CONTENT_STAGING)
				return VAU_STALE;
			if (p->root && p->role == VAU_CONTENT_SAVEDATA &&
			    !strncmp(p->path, prefix, strlen(prefix))) {
				live++;
			}

			if (p->root && p->role == VAU_CONTENT_STAGING && !strcmp(p->path, "ux0:temp/game"))
				staging++;

			struct vau_content_scope_path observed;

			rc = vau_content_scope_find(j, after, p->path, &observed);
			if (rc)
				return rc == 1 ? VAU_STALE : rc;
			if (observed.role != p->role || observed.root != p->root)
				return VAU_STALE;

			rc = scope_savedata_gone(&observed);
			if (rc)
				return rc;
		}

		cursor = page.next;
	} while (page.more);
	if (live != 1 || staging != 1 || seen_before != b.path_count)
		return VAU_STALE;

	/* Include AFTER-only descendants: a leftover renamed backup or newly
	 * observed staging file cannot disappear from the success predicate. */
	cursor = 0;
	do {
		rc = vau_content_scope_page(j, after, cursor, &page);
		if (rc)
			return rc;

		for (unsigned i = 0; i < page.count; i++) {
			++seen_after;
			rc = scope_savedata_gone(&page.entries[i]);
			if (rc)
				return rc;
		}

		cursor = page.next;
	} while (page.more);
	return seen_after == a.path_count ? 0 : VAU_STALE;
}

static int scope_media_observation_valid(const struct vau_content_scope *scope,
                                         const struct vau_content_media_observation *o)
{
	if (!o || scope->request.kind < VAU_CONTENT_PHOTO || scope->request.kind > VAU_CONTENT_VIDEO ||
	    o->state > VAU_MEDIA_PRESENT) {
		return 0;
	}

	if (scope->phase != VAU_CONTENT_SCOPE_AFTER && o->state != VAU_MEDIA_PRESENT)
		return 0;

	const struct vau_content_media_record *r = &o->record;

	if (o->state == VAU_MEDIA_PRESENT) {
		return !o->error && vau_content_media_record_valid(r) && r->id == scope->request.media_id &&
		       r->category == scope->request.kind - VAU_CONTENT_PHOTO + 1;
	}

	if (r->id || r->bytes || r->category || r->status || r->bytes_known || r->path[0])
		return 0;
	return o->state == VAU_MEDIA_UNKNOWN ? o->error < 0 : !o->error;
}

int vau_content_scope_media_add(struct vau_content_scope_writer *w,
                                const struct vau_content_media_observation *o)
{
	if (!scope_active(w))
		return VAU_INVALID;
	if (w->failure)
		return w->failure;
	if (w->media_added || !scope_media_observation_valid(&w->scope, o))
		return scope_fail(w, VAU_INVALID);

	char values[8][24];

	vau_snprintf(values[0], 24, "%llu", (unsigned long long)w->scope.sequence);
	vau_snprintf(values[1], 24, "%u", o->state);
	vau_snprintf(values[2], 24, "%d", o->error);
	vau_snprintf(values[3], 24, "%u", o->record.category);
	vau_snprintf(values[4], 24, "%llu", (unsigned long long)o->record.id);
	vau_snprintf(values[5], 24, "%u", o->record.status);
	vau_snprintf(values[6], 24, "%u", o->record.bytes_known);
	vau_snprintf(values[7], 24, "%llu", (unsigned long long)o->record.bytes);

	const char *parameters[] = {
		values[0],      values[1], values[2], values[3], values[4],
		o->record.path, values[5], values[6], values[7],
	};
	sqlite3_stmt *s = NULL;

	int rc = scope_prepare(w->journal->db,
	                       "INSERT INTO "
	                       "content_media_snapshots(scope_sequence,state,error,"
	                       "category,media_id,path,status,bytes_known,bytes) "
	                       "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
	                       &s);

	for (unsigned i = 0; i < 9 && !rc; i++)
		rc = scope_bind(s, (int)i + 1, parameters[i]);
	if (!rc)
		rc = scope_done(s);
	rc = scope_finish(s, rc);
	if (!rc)
		w->media_added = 1;
	return scope_fail(w, rc);
}

int vau_content_scope_media_get(struct vau_content_journal *j, uint64_t sequence,
                                struct vau_content_media_observation *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	struct vau_content_scope scope;
	int rc = vau_content_scope_get(j, sequence, &scope);

	if (rc)
		return rc;
	if (scope.request.kind < VAU_CONTENT_PHOTO)
		return VAU_INVALID;

	char id[24];

	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)sequence);

	sqlite3_stmt *s = NULL;

	rc = scope_prepare(j->db,
	                   "SELECT state,error,category,media_id,path,status,bytes_known,bytes "
	                   "FROM content_media_snapshots WHERE scope_sequence=CAST(?1 AS INTEGER)",
	                   &s);
	if (!rc)
		rc = scope_bind(s, 1, id);

	struct vau_content_media_observation found = { 0 };

	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 100 ? 0 : step == 101 ? VAU_DEVICE_ERROR : scope_error(step);

		uint64_t n = 0;

		if (!rc)
			rc = scope_number(s, 0, VAU_MEDIA_PRESENT, &n);
		found.state = (unsigned)n;
		if (!rc)
			rc = scope_signed_number(s, 1, &found.error);
		if (!rc)
			rc = scope_number(s, 2, 3, &n);
		found.record.category = (unsigned)n;
		if (!rc)
			rc = scope_number(s, 3, INT64_MAX, &found.record.id);
		if (!rc && sqlite3_column_type(s, 4) != 3)
			rc = VAU_DEVICE_ERROR;
		if (!rc)
			rc = scope_text(s, 4, found.record.path, sizeof(found.record.path));
		if (!rc)
			rc = scope_number(s, 5, UINT32_MAX, &n);
		found.record.status = (unsigned)n;
		if (!rc)
			rc = scope_number(s, 6, 1, &n);
		found.record.bytes_known = (unsigned)n;
		if (!rc)
			rc = scope_number(s, 7, INT64_MAX, &found.record.bytes);
		if (!rc && !scope_media_observation_valid(&scope, &found))
			rc = VAU_DEVICE_ERROR;
		if (!rc) {
			step = sqlite3_step(s);
			if (step != 101)
				rc = step == 100 ? VAU_DEVICE_ERROR : scope_error(step);
		}
	}

	rc = scope_finish(s, rc);
	if (!rc)
		*out = found;
	return rc;
}

static int scope_album_active(struct vau_content_scope_writer *w)
{
	return scope_active(w) && w->media_added && w->scope.request.kind >= VAU_CONTENT_PHOTO &&
	       !w->albums_finished && !w->failure;
}

int vau_content_scope_album_link_add(struct vau_content_scope_writer *w,
                                     const struct vau_content_media_link *o)
{
	if (!scope_album_active(w))
		return VAU_INVALID;
	if (!o || !o->id || o->id > INT64_MAX || o->list_id > INT64_MAX)
		return scope_fail(w, VAU_INVALID);

	w->albums_started = 1;

	char values[4][24];
	const uint64_t numbers[] = { w->scope.sequence, o->id, o->list_id, o->item_type };

	for (unsigned i = 0; i < 4; i++)
		vau_snprintf(values[i], sizeof(values[i]), "%llu", (unsigned long long)numbers[i]);

	sqlite3_stmt *s = NULL;
	int rc          = scope_prepare(w->journal->db,
	                                "INSERT INTO content_media_links(scope_sequence,id,list_id,item_type) "
	                                         "VALUES(CAST(?1 AS INTEGER),?2,?3,CAST(?4 AS INTEGER))",
	                                &s);

	for (unsigned i = 0; i < 4 && !rc; i++)
		rc = scope_bind(s, i + 1, values[i]);
	if (!rc)
		rc = scope_done(s);
	return scope_fail(w, scope_finish(s, rc));
}

int vau_content_scope_album_list_add(struct vau_content_scope_writer *w,
                                     const struct vau_content_media_list *o)
{
	if (!scope_album_active(w))
		return VAU_INVALID;
	if (!o || o->id > INT64_MAX || o->registered > 1 || o->items > INT64_MAX ||
	    o->target_items > o->items) {
		return scope_fail(w, VAU_INVALID);
	}

	w->albums_started = 1;

	char values[5][24];
	const uint64_t numbers[] = {
		w->scope.sequence, o->id, o->registered, o->items, o->target_items,
	};

	for (unsigned i = 0; i < 5; i++)
		vau_snprintf(values[i], sizeof(values[i]), "%llu", (unsigned long long)numbers[i]);

	sqlite3_stmt *s = NULL;
	int rc          = scope_prepare(w->journal->db,
	                                "INSERT INTO "
	                                         "content_media_lists(scope_sequence,list_id,registered,"
	                                         "items,target_items) "
	                                         "VALUES(CAST(?1 AS INTEGER),?2,CAST(?3 AS INTEGER),?4,?5)",
	                                &s);

	for (unsigned i = 0; i < 5 && !rc; i++)
		rc = scope_bind(s, i + 1, values[i]);
	if (!rc)
		rc = scope_done(s);
	return scope_fail(w, scope_finish(s, rc));
}

int vau_content_scope_albums_finish(struct vau_content_scope_writer *w)
{
	if (!scope_album_active(w))
		return VAU_INVALID;

	char id[24];

	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)w->scope.sequence);

	sqlite3_stmt *s = NULL;
	int rc          = scope_prepare(w->journal->db,
	                                "SELECT 1 FROM content_media_links a WHERE "
	                                         "a.scope_sequence=CAST(?1 AS INTEGER) "
	                                         "AND NOT EXISTS(SELECT 1 FROM content_media_lists b "
	                                         "WHERE b.scope_sequence=a.scope_sequence "
	                                         "AND b.list_id=a.list_id) UNION ALL SELECT 1 FROM "
	                                         "content_media_lists a WHERE "
	                                         "a.scope_sequence=CAST(?1 AS INTEGER) AND "
	                                         "CAST(a.target_items AS INTEGER)!="
	                                         "(SELECT count(*) FROM content_media_links b WHERE "
	                                         "b.scope_sequence=a.scope_sequence "
	                                         "AND b.list_id=a.list_id) LIMIT 1",
	                                &s);

	if (!rc)
		rc = scope_bind(s, 1, id);
	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 101 ? 0 : step == 100 ? VAU_INVALID : scope_error(step);
	}

	rc = scope_finish(s, rc);
	s  = NULL;
	if (!rc) {
		rc = scope_prepare(w->journal->db,
		                   "INSERT INTO content_media_album_sets(scope_sequence,links,lists) "
		                   "SELECT "
		                   "CAST(?1 AS INTEGER),(SELECT count(*) FROM content_media_links WHERE "
		                   "scope_sequence=CAST(?1 AS INTEGER)),"
		                   "(SELECT count(*) FROM content_media_lists WHERE "
		                   "scope_sequence=CAST(?1 AS INTEGER))",
		                   &s);
	}

	if (!rc)
		rc = scope_bind(s, 1, id);
	if (!rc)
		rc = scope_done(s);
	rc = scope_finish(s, rc);
	if (!rc)
		w->albums_finished = 1;
	return scope_fail(w, rc);
}

static int scope_albums_read(struct vau_content_journal *j, uint64_t sequence,
                             struct vau_content_album_set *out,
                             const struct vau_content_scope_writer *owner)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	struct vau_content_scope scope;
	int rc = scope_scope_read(j, sequence, &scope, owner);

	if (rc)
		return rc;
	if (scope.request.kind < VAU_CONTENT_PHOTO)
		return VAU_INVALID;

	char id[24];

	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)sequence);

	sqlite3_stmt *s = NULL;

	rc = scope_prepare(j->db,
	                   "SELECT links,lists,"
	                   "(SELECT count(*) FROM content_media_links WHERE scope_sequence=CAST(?1 "
	                   "AS INTEGER)),"
	                   "(SELECT count(*) FROM content_media_lists WHERE scope_sequence=CAST(?1 "
	                   "AS INTEGER)),"
	                   "(SELECT count(*) FROM content_media_links a WHERE "
	                   "a.scope_sequence=CAST(?1 AS INTEGER) AND "
	                   "NOT EXISTS "
	                   "(SELECT 1 FROM content_media_lists b WHERE "
	                   "b.scope_sequence=a.scope_sequence AND "
	                   "b.list_id=a.list_id))+(SELECT count(*) FROM content_media_lists a WHERE "
	                   "a.scope_sequence=CAST(?1 AS INTEGER) AND CAST(a.target_items AS "
	                   "INTEGER)!="
	                   "(SELECT count(*) FROM content_media_links b WHERE "
	                   "b.scope_sequence=a.scope_sequence "
	                   "AND b.list_id=a.list_id)) "
	                   "FROM content_media_album_sets WHERE scope_sequence=CAST(?1 AS INTEGER)",
	                   &s);
	if (!rc)
		rc = scope_bind(s, 1, id);

	struct vau_content_album_set found = { 0 };
	uint64_t links = 0, lists = 0, missing = 0;

	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 100 ? 0 : step == 101 ? 1 : scope_error(step);
		if (!rc)
			rc = scope_number(s, 0, INT64_MAX, &found.links);
		if (!rc)
			rc = scope_number(s, 1, INT64_MAX, &found.lists);
		if (!rc)
			rc = scope_number(s, 2, INT64_MAX, &links);
		if (!rc)
			rc = scope_number(s, 3, INT64_MAX, &lists);
		if (!rc)
			rc = scope_number(s, 4, INT64_MAX, &missing);
		if (!rc && (links != found.links || lists != found.lists || missing))
			rc = VAU_DEVICE_ERROR;
		if (!rc) {
			step = sqlite3_step(s);
			if (step != 101)
				rc = step == 100 ? VAU_DEVICE_ERROR : scope_error(step);
		}
	}

	rc = scope_finish(s, rc);
	if (!rc)
		*out = found;
	return rc;
}

int vau_content_scope_albums_get(struct vau_content_journal *j, uint64_t sequence,
                                 struct vau_content_album_set *out)
{
	return scope_albums_read(j, sequence, out, NULL);
}

int vau_content_scope_albums_page(struct vau_content_journal *j, uint64_t sequence,
                                  uint64_t link_cursor, uint64_t list_cursor,
                                  struct vau_content_album_page *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (link_cursor > INT64_MAX || list_cursor > INT64_MAX)
		return VAU_INVALID;

	struct vau_content_scope scope;
	int rc = vau_content_scope_get(j, sequence, &scope);

	if (rc)
		return rc;
	if (scope.request.kind < VAU_CONTENT_PHOTO)
		return VAU_INVALID;

	/* A single indexed marker lookup on each page, not a complete membership
	 * recount per chunk. The collecting host verifies counts and list links. */
	char scope_id[24], cursors[2][24];

	vau_snprintf(scope_id, sizeof(scope_id), "%llu", (unsigned long long)sequence);
	vau_snprintf(cursors[0], sizeof(cursors[0]), "%llu", (unsigned long long)link_cursor);
	vau_snprintf(cursors[1], sizeof(cursors[1]), "%llu", (unsigned long long)list_cursor);

	struct vau_content_album_page page = { .next_link = link_cursor, .next_list = list_cursor };
	sqlite3_stmt *s                    = NULL;

	rc = scope_prepare(j->db,
	                   "SELECT links,lists FROM content_media_album_sets WHERE "
	                   "scope_sequence=CAST(?1 AS INTEGER)",
	                   &s);
	if (!rc)
		rc = scope_bind(s, 1, scope_id);
	if (!rc) {
		int step = sqlite3_step(s);

		if (step == 100) {
			page.known = 1;
			rc         = scope_number(s, 0, INT64_MAX, &page.set.links);
			if (!rc)
				rc = scope_number(s, 1, INT64_MAX, &page.set.lists);
			if (!rc && sqlite3_step(s) != 101)
				rc = VAU_DEVICE_ERROR;
		} else if (step != 101) {
			rc = scope_error(step);
		}
	}

	rc = scope_finish(s, rc);
	s  = NULL;
	for (unsigned side = 0; page.known && side < 2 && !rc; side++) {
		if (!(side ? page.set.lists : page.set.links))
			continue;

		/* NOT INDEXED makes the rowid cursor seek directly. Rows of a committed
		 * scope are immutable; unrelated later scopes cannot reorder them. */
		const char *sql = side ? "SELECT rowid,list_id,registered,items,target_items FROM "
		                         "content_media_lists NOT INDEXED WHERE rowid>CAST(?2 AS INTEGER) "
		                         "AND scope_sequence=CAST(?1 AS INTEGER) ORDER BY rowid LIMIT 9"
		                       : "SELECT rowid,id,list_id,item_type FROM content_media_links NOT "
		                         "INDEXED WHERE rowid>CAST(?2 AS INTEGER) AND "
		                         "scope_sequence=CAST(?1 AS INTEGER) ORDER BY rowid LIMIT 9";

		rc = scope_prepare(j->db, sql, &s);
		if (!rc)
			rc = scope_bind(s, 1, scope_id);
		if (!rc)
			rc = scope_bind(s, 2, cursors[side]);

		unsigned count = 0;
		uint64_t last  = side ? list_cursor : link_cursor;

		while (!rc) {
			int step = sqlite3_step(s);

			if (step == 101)
				break;
			if (step != 100) {
				rc = scope_error(step);
				break;
			}

			uint64_t v[5] = { 0 };

			for (unsigned i = 0; i < (side ? 5u : 4u) && !rc; i++)
				rc = scope_number(s, i, INT64_MAX, &v[i]);
			if (!rc &&
			    (v[0] <= last || (side ? v[2] > 1 || v[4] > v[3] : !v[1] || v[3] > UINT_MAX))) {
				rc = VAU_DEVICE_ERROR;
			}

			if (rc)
				break;
			if (count == VAU_CONTENT_ALBUM_PAGE_ROWS) {
				page.more = 1;
				break;
			}

			last = v[0];
			if (side) {
				page.lists[count] = (struct vau_content_media_list){
					.id = v[1], .registered = (unsigned)v[2], .items = v[3], .target_items = v[4]
				};
			} else {
				page.links[count] = (struct vau_content_media_link){ .id        = v[1],
					                                                 .list_id   = v[2],
					                                                 .item_type = (unsigned)v[3] };
			}

			count++;
		}

		rc = scope_finish(s, rc);
		s  = NULL;
		if (side) {
			page.list_count = count;
			page.next_list  = last;
		} else {
			page.link_count = count;
			page.next_link  = last;
		}
	}

	if (!rc && (page.link_count > page.set.links || page.list_count > page.set.lists))
		rc = VAU_DEVICE_ERROR;
	if (!rc)
		*out = page;
	return rc;
}

static int scope_albums_visit(struct vau_content_journal *j, uint64_t sequence,
                              vau_content_album_visit visit, void *context,
                              const struct vau_content_scope_writer *owner)
{
	if (!visit)
		return VAU_INVALID;

	struct vau_content_album_set set;
	int rc = scope_albums_read(j, sequence, &set, owner);

	if (rc)
		return rc;

	char id[24];

	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)sequence);

	sqlite3_stmt *s = NULL;

	rc = scope_prepare(j->db,
	                   "SELECT 0,id,list_id,item_type,'0','0' FROM content_media_links "
	                   "WHERE scope_sequence=CAST(?1 AS INTEGER) UNION ALL SELECT "
	                   "1,list_id,'0',registered,items,target_items "
	                   "FROM content_media_lists WHERE scope_sequence=CAST(?1 AS INTEGER)",
	                   &s);
	if (!rc)
		rc = scope_bind(s, 1, id);

	uint64_t links = 0, lists = 0;

	while (!rc) {
		int step = sqlite3_step(s);

		if (step == 101)
			break;
		if (step != 100) {
			rc = scope_error(step);
			break;
		}

		uint64_t values[6] = { 0 };

		for (unsigned i = 0; i < 6 && !rc; i++)
			rc = scope_number(s, i, i == 0 ? 1 : INT64_MAX, &values[i]);
		if (rc)
			break;

		struct vau_content_album_entry entry = { .is_list = (unsigned)values[0] };

		if (entry.is_list) {
			if (values[2] || values[3] > 1 || values[5] > values[4])
				rc = VAU_DEVICE_ERROR;
			entry.list = (struct vau_content_media_list){ .id           = values[1],
				                                          .registered   = (unsigned)values[3],
				                                          .items        = values[4],
				                                          .target_items = values[5] };
			lists++;
		} else {
			if (!values[1] || values[3] > UINT_MAX || values[4] || values[5])
				rc = VAU_DEVICE_ERROR;
			entry.link = (struct vau_content_media_link){ .id        = values[1],
				                                          .list_id   = values[2],
				                                          .item_type = (unsigned)values[3] };
			links++;
		}

		if (!rc)
			rc = visit(context, &entry);
	}

	if (!rc && (links != set.links || lists != set.lists))
		rc = VAU_DEVICE_ERROR;
	return scope_finish(s, rc);
}

int vau_content_scope_albums_visit(struct vau_content_journal *j, uint64_t sequence,
                                   vau_content_album_visit visit, void *context)
{
	return scope_albums_visit(j, sequence, visit, context, NULL);
}

int vau_content_scope_source_albums_visit(struct vau_content_scope_writer *w, uint64_t sequence,
                                          vau_content_album_visit visit, void *context)
{
	if (!scope_active(w) || w->scope.phase != VAU_CONTENT_SCOPE_AFTER || w->failure)
		return VAU_INVALID;
	return scope_albums_visit(w->journal, sequence, visit, context, w);
}

int vau_content_scope_album_list_seen(struct vau_content_scope_writer *w, uint64_t list)
{
	if (!scope_album_active(w) || list > INT64_MAX)
		return VAU_INVALID;

	char scope[24], id[24];

	vau_snprintf(scope, sizeof(scope), "%llu", (unsigned long long)w->scope.sequence);
	vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)list);

	sqlite3_stmt *s = NULL;
	int rc          = scope_prepare(w->journal->db,
	                                "SELECT 1 FROM content_media_lists WHERE "
	                                         "scope_sequence=CAST(?1 AS INTEGER) AND list_id=?2",
	                                &s);

	if (!rc)
		rc = scope_bind(s, 1, scope);
	if (!rc)
		rc = scope_bind(s, 2, id);

	int found = 0;

	if (!rc) {
		int step = sqlite3_step(s);

		if (step == 100)
			found = 1;
		else if (step != 101)
			rc = scope_error(step);
	}

	rc = scope_finish(s, rc);
	return rc ? scope_fail(w, rc) : found;
}

static int media_complete_known(const struct vau_content_scope_path *p)
{
	return p->observation.state == VAU_STATE_UNKNOWN ? p->observation.error : 0;
}

static int media_complete_equal_info(const struct vau_file_info *a, const struct vau_file_info *b)
{
	return a->bytes == b->bytes && a->mode == b->mode && a->attributes == b->attributes &&
	       a->kind == b->kind && a->year == b->year && a->month == b->month && a->day == b->day &&
	       a->hour == b->hour && a->minute == b->minute && a->second == b->second &&
	       a->microsecond == b->microsecond;
}

static int media_complete_under(const char *p, const char *root)
{
	size_t n = strlen(root);

	return !strncmp(p, root, n) && (!p[n] || p[n] == '/');
}

int vau_content_scope_media_complete(struct vau_content_journal *j, uint64_t before, uint64_t after)
{
	struct vau_content_scope b, a;
	int rc = vau_content_scope_get(j, before, &b);

	if (!rc)
		rc = vau_content_scope_get(j, after, &a);
	if (rc)
		return rc == 1 ? VAU_STALE : rc;
	if (b.request.kind < VAU_CONTENT_PHOTO || b.phase != VAU_CONTENT_SCOPE_BEFORE ||
	    a.phase != VAU_CONTENT_SCOPE_AFTER || after <= before ||
	    !vau_content_delete_target_same(&a.request, &b.request)) {
		return VAU_STALE;
	}

	struct vau_content_media_observation source;

	rc = vau_content_scope_media_get(j, before, &source);
	if (rc)
		return rc;
	if (source.state != VAU_MEDIA_PRESENT || source.record.status != 2)
		return VAU_STALE;

	rc = vau_content_scope_media_get(j, after, &source);
	if (rc)
		return rc;
	if (source.state == VAU_MEDIA_UNKNOWN)
		return source.error;
	if (source.state != VAU_MEDIA_ABSENT)
		return VAU_STALE;

	struct vau_content_album_set albums;

	rc = vau_content_scope_albums_get(j, before, &albums);
	if (rc)
		return rc == 1 ? VAU_STALE : rc;

	uint64_t before_lists = albums.lists;

	rc = vau_content_scope_albums_get(j, after, &albums);
	if (rc)
		return rc == 1 ? VAU_STALE : rc;
	if (albums.links || albums.lists != before_lists)
		return VAU_STALE;

	/* The native cleanup may remove only its selected empty list. Empty list
	 * registrations are not a failure by themselves. Saved BEFORE lists must
	 * still have an AFTER observation with no remaining target membership. */
	sqlite3_stmt *s = NULL;

	rc = sqlite3_prepare_v2(j->db,
	                        "SELECT 1 FROM content_media_lists b WHERE "
	                        "b.scope_sequence=CAST(?1 AS INTEGER) AND NOT EXISTS"
	                        "(SELECT 1 FROM content_media_lists a WHERE "
	                        "a.scope_sequence=CAST(?2 AS INTEGER) AND "
	                        "a.list_id=b.list_id) LIMIT 1",
	                        -1, &s, NULL);

	char ids[2][24];

	vau_snprintf(ids[0], sizeof(ids[0]), "%llu", (unsigned long long)before);
	vau_snprintf(ids[1], sizeof(ids[1]), "%llu", (unsigned long long)after);
	for (unsigned i = 0; i < 2 && !rc; i++)
		rc = sqlite3_bind_text(s, i + 1, ids[i], -1, NULL);
	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 101 ? 0 : step == 100 ? VAU_STALE : -65536 - step;
	} else {
		rc = -65536 - rc;
	}

	if (s) {
		int end = sqlite3_finalize(s);

		if (!rc && end)
			rc = -65536 - end;
	}

	if (rc)
		return rc;

	static const char *const categories[] = { "photo", "music", "video" };
	static const char *const roots[]      = { "ux0:picture/", "ux0:music/", "ux0:video/" };

	unsigned category = b.request.kind - VAU_CONTENT_PHOTO;
	char database[96], journal[112], temp[VAU_PATH_MAX] = { 0 };

	vau_snprintf(database, sizeof(database), "ux0:mms/%s/AVContent.db", categories[category]);
	vau_snprintf(journal, sizeof(journal), "%s-journal", database);

	struct vau_content_scope_page page;
	uint64_t cursor = 0, seen = 0;
	unsigned temp_roots = 0, databases = 0, journals = 0, mains = 0;

	/* Find the saved temp root first, independently of insertion order. */
	do {
		rc = vau_content_scope_page(j, before, cursor, &page);
		if (rc)
			return rc;

		for (unsigned i = 0; i < page.count; i++) {
			const struct vau_content_scope_path *p = &page.entries[i];

			if (p->role == VAU_CONTENT_MEDIA_TEMP && p->root) {
				if (temp_roots++)
					return VAU_STALE;

				strcpy(temp, p->path);
			}
		}

		cursor = page.next;
	} while (page.more);
	if (temp_roots != 1)
		return VAU_STALE;

	cursor = 0;
	do {
		rc = vau_content_scope_page(j, before, cursor, &page);
		if (rc)
			return rc;

		for (unsigned i = 0; i < page.count; i++) {
			const struct vau_content_scope_path *p = &page.entries[i];
			struct vau_content_scope_path q;

			rc = media_complete_known(p);
			if (rc)
				return rc;

			rc = vau_content_scope_find(j, after, p->path, &q);
			if (rc)
				return rc == 1 ? VAU_STALE : rc;
			if (q.role != p->role || q.root != p->root)
				return VAU_STALE;

			rc = media_complete_known(&q);
			if (rc)
				return rc;

			unsigned left = p->observation.state, right = q.observation.state;

			switch (p->role) {
			case VAU_CONTENT_MEDIA_DATABASE:
				if (!p->root || strcmp(p->path, database) || databases++ ||
				    left != VAU_STATE_FILE || right != VAU_STATE_FILE) {
					return VAU_STALE;
				}
				break;
			case VAU_CONTENT_MEDIA_JOURNAL:
				if (!p->root || strcmp(p->path, journal) || journals++ ||
				    (left != VAU_STATE_FILE && left != VAU_STATE_MISSING) ||
				    (right != VAU_STATE_FILE && right != VAU_STATE_MISSING)) {
					return VAU_STALE;
				}
				break;
			case VAU_CONTENT_MEDIA_FILE:
			case VAU_CONTENT_MEDIA_RELATED:
				if (!p->root || strncmp(p->path, roots[category], strlen(roots[category])) ||
				    (left != VAU_STATE_FILE && left != VAU_STATE_MISSING) ||
				    right != VAU_STATE_MISSING) {
					return VAU_STALE;
				}

				if (p->role == VAU_CONTENT_MEDIA_FILE && (mains++ || left != VAU_STATE_FILE))
					return VAU_STALE;
				break;
			case VAU_CONTENT_MEDIA_TEMP:
				if (!media_complete_under(p->path, temp))
					return VAU_STALE;
				if (p->root) {
					if ((left != VAU_STATE_DIRECTORY && left != VAU_STATE_MISSING) ||
					    (right != VAU_STATE_DIRECTORY && right != VAU_STATE_MISSING) ||
					    (left == VAU_STATE_DIRECTORY && right != VAU_STATE_DIRECTORY)) {
						return VAU_STALE;
					}
				} else if (left != right ||
				           !media_complete_equal_info(&p->observation.info, &q.observation.info)) {
					return VAU_STALE;
				}
				break;
			default: return VAU_STALE;
			}

			seen++;
		}

		cursor = page.next;
	} while (page.more);

	/* Every BEFORE path was found. Equal cardinality also rules out newly
	 * observed leftover temp files. Metadata equality is not a content hash. */
	return databases == 1 && journals == 1 && mains == 1 && seen == b.path_count &&
	                       a.path_count == b.path_count
	               ? 0
	               : VAU_STALE;
}
