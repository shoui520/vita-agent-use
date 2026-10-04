/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "content_journal.h"
#include "content_scope.h"
#include "format.h"
#include <limits.h>
#include <string.h>
#ifdef VAU_NATIVE_FORMAT
#include "sqlite_memory.h"
#include "sqlite_vfs.h"
#endif
static const char fields[] =
    "sequence,subject,operation_id,title,yes,state,before_registry,before_application,after_known,after_"
    "registry,after_application,effect_started,result,observed_us,scope_sequence,requested_preview,operation_"
    "kind,target_user,media_id";
static int error(int rc) { return rc ? -65536 - rc : 0; }
static int prepare(sqlite3 *db, const char *sql, sqlite3_stmt **s) {
    return error(sqlite3_prepare_v2(db, sql, -1, s, NULL));
}
static int text(sqlite3_stmt *s, int index, char *out, size_t cap) {
    const unsigned char *p = sqlite3_column_text(s, index);
    int n = sqlite3_column_bytes(s, index);
    if (!p || n < 0 || (size_t)n >= cap || memchr(p, 0, (size_t)n))
        return VAU_DEVICE_ERROR;
    memcpy(out, p, (size_t)n);
    out[n] = 0;
    return 0;
}
static int number(sqlite3_stmt *s, int index, uint64_t max, uint64_t *out) {
    char buffer[24];
    int rc = text(s, index, buffer, sizeof(buffer));
    if (rc)
        return rc;
    uint64_t value = 0;
    for (const char *p = buffer; *p; p++) {
        if (*p < '0' || *p > '9' || value > max / 10 ||
            (value == max / 10 && (unsigned)(*p - '0') > max % 10))
            return VAU_DEVICE_ERROR;
        value = value * 10 + (unsigned)(*p - '0');
    }
    *out = value;
    return 0;
}
static int decode(sqlite3_stmt *s, struct vau_content_audit_event *e) {
    memset(e, 0, sizeof(*e));
    struct vau_content_delete_record *r = &e->record;
    uint64_t n;
    int rc;
#define NUM(i, max, target)                                                                                  \
    do {                                                                                                     \
        rc = number(s, i, max, &n);                                                                          \
        if (rc)                                                                                              \
            return rc;                                                                                       \
        target = n;                                                                                          \
    } while (0)
    NUM(0, INT64_MAX, e->sequence);
    if ((rc = text(s, 1, r->request.subject, sizeof(r->request.subject))) ||
        (rc = text(s, 2, r->request.id, sizeof(r->request.id))) ||
        (rc = text(s, 3, r->request.title, sizeof(r->request.title))))
        return rc;
    NUM(4, 1, r->request.yes);
    NUM(5, VAU_CONTENT_DELETE_UNCERTAIN, r->state);
    NUM(6, 1, r->before.registered);
    NUM(7, 1, r->before.application_present);
    NUM(8, 1, r->after_known);
    NUM(9, 1, r->after.registered);
    NUM(10, 1, r->after.application_present);
    NUM(11, 1, r->effect_started);
    char result[24];
    rc = text(s, 12, result, sizeof(result));
    if (rc)
        return rc;
    const char *p = result;
    int negative = *p == '-';
    if (negative)
        p++;
    if (!*p)
        return VAU_DEVICE_ERROR;
    uint64_t value = 0, max = negative ? (uint64_t)INT_MAX + 1 : INT_MAX;
    for (; *p; p++) {
        if (*p < '0' || *p > '9' || value > max / 10 ||
            (value == max / 10 && (unsigned)(*p - '0') > max % 10))
            return VAU_DEVICE_ERROR;
        value = value * 10 + (unsigned)(*p - '0');
    }
    r->result = negative ? value == (uint64_t)INT_MAX + 1 ? INT_MIN : -(int)value : (int)value;
    NUM(13, INT64_MAX, r->observed_us);
    NUM(14, INT64_MAX, r->scope_sequence);
    NUM(15, INT64_MAX, r->request.preview_sequence);
    NUM(16, VAU_CONTENT_VIDEO, r->request.kind);
    NUM(17, 63, r->request.user);
    NUM(18, INT64_MAX, r->request.media_id);
#undef NUM
    return e->sequence && vau_content_delete_record_valid(r) ? 0 : VAU_DEVICE_ERROR;
}
static int bound_scope(struct vau_content_journal *j, const struct vau_content_delete_record *r) {
    if (!r->scope_sequence)
        return r->request.preview_sequence ? VAU_STALE : 0; /* Migrated history. */
    if (r->request.preview_sequence) {
        struct vau_content_scope preview;
        int checked = vau_content_scope_get(j, r->request.preview_sequence, &preview);
        if (checked)
            return checked == 1 ? VAU_STALE : checked;
        if (preview.phase != VAU_CONTENT_SCOPE_PREVIEW ||
            !vau_content_delete_target_same(&preview.request, &r->request) ||
            r->request.preview_sequence > r->scope_sequence)
            return VAU_STALE;
    }
    sqlite3_stmt *s = NULL;
    char id[24];
    vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)r->scope_sequence);
    int rc = prepare(
        j->db,
        "SELECT subject,operation_id,title,phase,path_count,"
        "(SELECT COUNT(*) FROM content_scope_paths WHERE scope_sequence=content_scopes.sequence),"
        "(SELECT COUNT(*) FROM content_scope_paths WHERE scope_sequence=content_scopes.sequence AND state=0) "
        ",operation_kind,target_user,media_id FROM content_scopes WHERE sequence=CAST(?1 AS INTEGER)",
        &s);
    if (!rc)
        rc = error(sqlite3_bind_text(s, 1, id, -1, NULL));
    if (!rc) {
        int step = sqlite3_step(s);
        if (step == 101)
            rc = VAU_STALE;
        else if (step != 100)
            rc = error(step);
        else {
            char subject[65], operation[33], title[10];
            uint64_t phase = 0, count = 0, actual = 0, unknown = 0;
            if ((rc = text(s, 0, subject, sizeof(subject))) ||
                (rc = text(s, 1, operation, sizeof(operation))) || (rc = text(s, 2, title, sizeof(title))))
                goto finish;
            if (strcmp(subject, r->request.subject) || strcmp(operation, r->request.id) ||
                strcmp(title, r->request.title)) {
                rc = VAU_STALE;
                goto finish;
            }
            if ((rc = number(s, 3, VAU_CONTENT_SCOPE_AFTER, &phase)) ||
                (rc = number(s, 4, INT64_MAX, &count)) || (rc = number(s, 5, INT64_MAX, &actual)) ||
                (rc = number(s, 6, INT64_MAX, &unknown)))
                goto finish;
            uint64_t kind, user, media_id;
            if ((rc = number(s, 7, VAU_CONTENT_VIDEO, &kind)) || (rc = number(s, 8, 63, &user)) ||
                (rc = number(s, 9, INT64_MAX, &media_id)))
                goto finish;
            if (kind != r->request.kind || user != r->request.user || media_id != r->request.media_id) {
                rc = VAU_STALE;
                goto finish;
            }
            if (!count || count != actual ||
                (r->state == VAU_CONTENT_DELETE_APPROVAL && phase != VAU_CONTENT_SCOPE_PREVIEW) ||
                (r->state == VAU_CONTENT_DELETE_RUNNING && (phase != VAU_CONTENT_SCOPE_BEFORE || unknown)) ||
                (r->after_known && phase != VAU_CONTENT_SCOPE_AFTER) ||
                (r->state == VAU_CONTENT_DELETE_COMPLETE && (phase != VAU_CONTENT_SCOPE_AFTER || unknown)))
                rc = VAU_STALE;
        }
    }
finish:
    if (s) {
        int end = error(sqlite3_finalize(s));
        if (!rc)
            rc = end;
    }
    if (!rc && r->request.kind >= VAU_CONTENT_PHOTO) {
        struct vau_content_media_observation media;
        rc = vau_content_scope_media_get(j, r->scope_sequence, &media);
    }
    if (!rc && r->state == VAU_CONTENT_DELETE_COMPLETE && r->request.kind == VAU_CONTENT_VITA_SAVEDATA) {
        struct vau_content_scope before;
        rc = vau_content_scope_latest(j, &r->request, VAU_CONTENT_SCOPE_BEFORE, &before);
        if (rc == 1)
            rc = VAU_STALE;
        if (!rc)
            rc = vau_content_scope_savedata_complete(j, before.sequence, r->scope_sequence);
    }
    return rc;
}
int vau_content_journal_close(struct vau_content_journal *j) {
    if (!j || !j->db)
        return VAU_INVALID;
    if (j->scope_active)
        return VAU_BUSY;
    int rc = error(sqlite3_close(j->db));
    if (!rc)
        j->db = NULL;
    return rc;
}
int vau_content_journal_open(struct vau_content_journal *j, const char *path, int readonly) {
    if (!j || j->db || !path || (readonly != 0 && readonly != 1))
        return VAU_INVALID;
#ifdef VAU_NATIVE_FORMAT
    int rc = vau_sqlite_memory_configure();
    if (rc)
        return error(rc);
    rc = vau_sqlite_vfs_configure();
    if (rc)
        return error(rc);
#else
    int rc;
#endif
    sqlite3 *db = NULL;
    rc = error(sqlite3_open_v2(path, &db, readonly ? 1 : 6,
#ifdef VAU_NATIVE_FORMAT
                               VAU_JOURNAL_VFS
#else
                               NULL
#endif
                               ));
    if (rc) {
        if (db)
            sqlite3_close(db);
        return rc;
    }
    sqlite3_stmt *s = NULL;
    uint64_t version = 0;
    rc = prepare(db, "PRAGMA user_version", &s);
    if (!rc) {
        int step = sqlite3_step(s);
        rc = step == 100 ? number(s, 0, 7, &version) : error(step);
    }
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    if (!rc && readonly && version != 7)
        rc = VAU_STALE;
    if (!rc)
        rc = error(sqlite3_exec(db, "PRAGMA cache_size=16;PRAGMA temp_store=MEMORY", NULL, NULL, NULL));
    if (!rc && !readonly)
        rc = error(sqlite3_exec(db,
                                "PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;PRAGMA "
                                "cache_size=16;PRAGMA temp_store=MEMORY",
                                NULL, NULL, NULL));
    if (!rc && !readonly && !version)
        rc = error(sqlite3_exec(db,
                                "BEGIN IMMEDIATE;CREATE TABLE IF NOT EXISTS content_delete_events("
                                "sequence INTEGER PRIMARY KEY AUTOINCREMENT,subject TEXT NOT "
                                "NULL,operation_id TEXT NOT NULL,title TEXT NOT NULL,"
                                "yes INTEGER NOT NULL,state INTEGER NOT NULL,before_registry INTEGER NOT "
                                "NULL,before_application INTEGER NOT NULL,"
                                "after_known INTEGER NOT NULL,after_registry INTEGER NOT "
                                "NULL,after_application INTEGER NOT NULL,effect_started INTEGER NOT NULL,"
                                "result INTEGER NOT NULL,observed_us TEXT NOT NULL);"
                                "CREATE INDEX IF NOT EXISTS content_delete_identity ON "
                                "content_delete_events(subject,operation_id,sequence);"
                                "PRAGMA user_version=1;COMMIT",
                                NULL, NULL, NULL));
    if (!rc && !readonly && version < 2)
        rc = error(sqlite3_exec(
            db,
            "BEGIN IMMEDIATE;ALTER TABLE content_delete_events ADD COLUMN scope_sequence TEXT NOT NULL "
            "DEFAULT '0';CREATE TABLE content_scopes("
            "sequence INTEGER PRIMARY KEY AUTOINCREMENT,subject TEXT NOT NULL,operation_id TEXT NOT "
            "NULL,title TEXT NOT NULL,"
            "phase INTEGER NOT NULL,observed_us TEXT NOT NULL,path_count INTEGER NOT NULL DEFAULT 0);"
            "CREATE INDEX content_scope_identity ON content_scopes(subject,operation_id,phase,sequence);"
            "CREATE TABLE content_scope_paths(sequence INTEGER PRIMARY KEY AUTOINCREMENT,scope_sequence "
            "INTEGER NOT NULL,"
            "path TEXT NOT NULL,role INTEGER NOT NULL,is_root INTEGER NOT NULL,state INTEGER NOT NULL,error "
            "INTEGER NOT NULL,"
            "bytes TEXT NOT NULL,mode INTEGER NOT NULL,attributes INTEGER NOT NULL,modified TEXT NOT NULL,"
            "UNIQUE(scope_sequence,path));"
            "CREATE INDEX content_scope_cursor ON content_scope_paths(scope_sequence,sequence);"
            "PRAGMA user_version=2;COMMIT",
            NULL, NULL, NULL));
    if (!rc && !readonly && version < 3)
        rc = error(sqlite3_exec(db,
                                "BEGIN IMMEDIATE;ALTER TABLE content_delete_events ADD COLUMN "
                                "requested_preview TEXT NOT NULL DEFAULT '0';PRAGMA user_version=3;COMMIT",
                                NULL, NULL, NULL));
    if (!rc && !readonly && version < 4)
        rc = error(sqlite3_exec(
            db,
            "BEGIN IMMEDIATE;ALTER TABLE content_delete_events ADD COLUMN operation_kind INTEGER NOT NULL "
            "DEFAULT 0;"
            "ALTER TABLE content_delete_events ADD COLUMN target_user INTEGER NOT NULL DEFAULT 0;"
            "ALTER TABLE content_scopes ADD COLUMN operation_kind INTEGER NOT NULL DEFAULT 0;"
            "ALTER TABLE content_scopes ADD COLUMN target_user INTEGER NOT NULL DEFAULT 0;"
            "PRAGMA user_version=4;COMMIT",
            NULL, NULL, NULL));
    if (!rc && !readonly && version < 5)
        rc = error(sqlite3_exec(
            db,
            "BEGIN IMMEDIATE;ALTER TABLE content_delete_events ADD COLUMN media_id TEXT NOT NULL DEFAULT '0';"
            "ALTER TABLE content_scopes ADD COLUMN media_id TEXT NOT NULL DEFAULT '0';"
            "PRAGMA user_version=5;COMMIT",
            NULL, NULL, NULL));
    if (!rc && !readonly && version < 6)
        rc = error(sqlite3_exec(
            db,
            "BEGIN IMMEDIATE;CREATE TABLE content_media_snapshots("
            "scope_sequence INTEGER PRIMARY KEY,state INTEGER NOT NULL,error INTEGER NOT NULL,"
            "category INTEGER NOT NULL,media_id TEXT NOT NULL,path TEXT NOT NULL,status INTEGER NOT NULL,"
            "bytes_known INTEGER NOT NULL,bytes TEXT NOT NULL);PRAGMA user_version=6;COMMIT",
            NULL, NULL, NULL));
    if (!rc && !readonly && version < 7)
        rc = error(sqlite3_exec(
            db,
            "BEGIN IMMEDIATE;CREATE TABLE content_media_links(scope_sequence INTEGER NOT NULL,"
            "id TEXT NOT NULL,list_id TEXT NOT NULL,item_type INTEGER NOT NULL,PRIMARY "
            "KEY(scope_sequence,id));"
            "CREATE INDEX content_media_link_list ON content_media_links(scope_sequence,list_id);"
            "CREATE TABLE content_media_lists(scope_sequence INTEGER NOT NULL,list_id TEXT NOT NULL,"
            "registered INTEGER NOT NULL,items TEXT NOT NULL,target_items TEXT NOT NULL,PRIMARY "
            "KEY(scope_sequence,list_id));"
            "CREATE TABLE content_media_album_sets(scope_sequence INTEGER PRIMARY KEY,links INTEGER NOT "
            "NULL,lists INTEGER NOT NULL);"
            "PRAGMA user_version=7;COMMIT",
            NULL, NULL, NULL));
    if (!rc) {
        char sql[512];
        int n = vau_snprintf(sql, sizeof(sql), "SELECT %s FROM content_delete_events LIMIT 0", fields);
        rc = n > 0 && (size_t)n < sizeof(sql) ? prepare(db, sql, &s) : VAU_DEVICE_ERROR;
    }
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    if (!rc)
        rc = prepare(db,
                     "SELECT "
                     "sequence,subject,operation_id,title,phase,observed_us,path_count,operation_kind,target_"
                     "user,media_id FROM "
                     "content_scopes LIMIT 0",
                     &s);
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    if (!rc)
        rc = prepare(
            db,
            "SELECT sequence,scope_sequence,path,role,is_root,state,error,bytes,mode,attributes,modified "
            "FROM content_scope_paths LIMIT 0",
            &s);
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    if (!rc)
        rc = prepare(db,
                     "SELECT scope_sequence,state,error,category,media_id,path,status,bytes_known,bytes "
                     "FROM content_media_snapshots LIMIT 0",
                     &s);
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    if (!rc)
        rc = prepare(db,
                     "SELECT a.scope_sequence,a.links,a.lists,b.id,b.list_id,b.item_type,"
                     "c.registered,c.items,c.target_items FROM content_media_album_sets a LEFT JOIN "
                     "content_media_links b "
                     "ON a.scope_sequence=b.scope_sequence LEFT JOIN content_media_lists c ON "
                     "b.scope_sequence=c.scope_sequence "
                     "AND b.list_id=c.list_id LIMIT 0",
                     &s);
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    if (rc) {
        sqlite3_close(db);
        return rc;
    }
    j->db = db;
    j->scope_active = 0;
    return 0;
}
int vau_content_journal_lookup(void *ctx, const char *subject, const char *id,
                               struct vau_content_delete_record *out) {
    struct vau_content_journal *j = ctx;
    if (!j || !j->db || !subject || !id || !out)
        return VAU_INVALID;
    if (j->scope_active)
        return VAU_BUSY;
    char sql[512];
    int n = vau_snprintf(sql, sizeof(sql),
                         "SELECT %s FROM content_delete_events WHERE subject=?1 AND operation_id=?2 ORDER BY "
                         "sequence DESC LIMIT 1",
                         fields);
    if (n < 0 || (size_t)n >= sizeof(sql))
        return VAU_DEVICE_ERROR;
    sqlite3_stmt *s = NULL;
    int rc = prepare(j->db, sql, &s);
    if (!rc)
        rc = error(sqlite3_bind_text(s, 1, subject, -1, NULL));
    if (!rc)
        rc = error(sqlite3_bind_text(s, 2, id, -1, NULL));
    if (!rc) {
        int step = sqlite3_step(s);
        if (step == 101)
            rc = 1;
        else if (step == 100) {
            struct vau_content_audit_event event;
            rc = decode(s, &event);
            if (!rc)
                rc = bound_scope(j, &event.record);
            if (!rc)
                *out = event.record;
        } else
            rc = error(step);
    }
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    return rc;
}
int vau_content_journal_persist(void *ctx, const struct vau_content_delete_record *r) {
    struct vau_content_journal *j = ctx;
    if (!j || !j->db || !vau_content_delete_record_valid(r) || r->observed_us > INT64_MAX)
        return VAU_INVALID;
    if (j->scope_active)
        return VAU_BUSY;
    if (!r->scope_sequence)
        return VAU_INVALID;
    int rc = bound_scope(j, r);
    if (rc)
        return rc;
    sqlite3_stmt *s = NULL;
    rc = prepare(j->db,
                 "INSERT INTO "
                 "content_delete_events(subject,operation_id,title,yes,state,before_registry,before_"
                 "application,after_known,after_registry,after_application,effect_started,result,observed_us,"
                 "scope_sequence,requested_preview,operation_kind,target_user,media_id) "
                 "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
                 &s);
    if (!rc)
        rc = error(sqlite3_bind_text(s, 1, r->request.subject, -1, NULL));
    if (!rc)
        rc = error(sqlite3_bind_text(s, 2, r->request.id, -1, NULL));
    if (!rc)
        rc = error(sqlite3_bind_text(s, 3, r->request.title, -1, NULL));
    char storage[15][24];
    uint64_t values[] = {r->request.yes,
                         r->state,
                         r->before.registered,
                         r->before.application_present,
                         r->after_known,
                         r->after.registered,
                         r->after.application_present,
                         r->effect_started};
    for (unsigned i = 0; i < 8 && !rc; i++) {
        vau_snprintf(storage[i], 24, "%llu", (unsigned long long)values[i]);
        rc = error(sqlite3_bind_text(s, (int)i + 4, storage[i], -1, NULL));
    }
    if (!rc) {
        vau_snprintf(storage[8], 24, "%d", r->result);
        rc = error(sqlite3_bind_text(s, 12, storage[8], -1, NULL));
    }
    if (!rc) {
        vau_snprintf(storage[9], 24, "%llu", (unsigned long long)r->observed_us);
        rc = error(sqlite3_bind_text(s, 13, storage[9], -1, NULL));
    }
    if (!rc) {
        vau_snprintf(storage[10], 24, "%llu", (unsigned long long)r->scope_sequence);
        rc = error(sqlite3_bind_text(s, 14, storage[10], -1, NULL));
    }
    if (!rc) {
        vau_snprintf(storage[11], 24, "%llu", (unsigned long long)r->request.preview_sequence);
        rc = error(sqlite3_bind_text(s, 15, storage[11], -1, NULL));
    }
    if (!rc) {
        vau_snprintf(storage[12], 24, "%u", r->request.kind);
        rc = error(sqlite3_bind_text(s, 16, storage[12], -1, NULL));
    }
    if (!rc) {
        vau_snprintf(storage[13], 24, "%u", r->request.user);
        rc = error(sqlite3_bind_text(s, 17, storage[13], -1, NULL));
    }
    if (!rc) {
        vau_snprintf(storage[14], 24, "%llu", (unsigned long long)r->request.media_id);
        rc = error(sqlite3_bind_text(s, 18, storage[14], -1, NULL));
    }
    if (!rc) {
        int step = sqlite3_step(s);
        rc = step == 101 ? 0 : error(step);
    }
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    return rc;
}
int vau_content_journal_persist_scope(struct vau_content_journal *j,
                                      const struct vau_content_delete_record *r, uint64_t scope) {
    if (!r || !scope || scope > INT64_MAX)
        return VAU_INVALID;
    struct vau_content_delete_record record = *r;
    record.scope_sequence = scope;
    return vau_content_journal_persist(j, &record);
}
int vau_content_journal_page(struct vau_content_journal *j, uint64_t after,
                             struct vau_content_audit_page *out) {
    if (!j || !j->db || !out || after > INT64_MAX)
        return VAU_INVALID;
    if (j->scope_active)
        return VAU_BUSY;
    memset(out, 0, sizeof(*out));
    out->next = after;
    char sql[512], cursor[24];
    int n = vau_snprintf(
        sql, sizeof(sql),
        "SELECT %s FROM content_delete_events WHERE sequence>CAST(?1 AS INTEGER) ORDER BY sequence LIMIT 3",
        fields);
    if (n < 0 || (size_t)n >= sizeof(sql))
        return VAU_DEVICE_ERROR;
    vau_snprintf(cursor, sizeof(cursor), "%llu", (unsigned long long)after);
    sqlite3_stmt *s = NULL;
    int rc = prepare(j->db, sql, &s);
    if (!rc)
        rc = error(sqlite3_bind_text(s, 1, cursor, -1, NULL));
    if (!rc)
        for (;;) {
            int step = sqlite3_step(s);
            if (step == 101)
                break;
            if (step != 100) {
                rc = error(step);
                break;
            }
            if (out->count == 2) {
                out->more = 1;
                break;
            }
            struct vau_content_audit_event *e = &out->events[out->count];
            rc = decode(s, e);
            if (!rc)
                rc = bound_scope(j, &e->record);
            if (rc)
                break;
            if (e->sequence <= out->next) {
                rc = VAU_STALE;
                break;
            }
            out->next = e->sequence;
            out->count++;
        }
    if (s) {
        int end = error(sqlite3_finalize(s));
        s = NULL;
        if (!rc)
            rc = end;
    }
    return rc;
}
int vau_content_journal_scope_lookup(struct vau_content_journal *j, uint64_t scope,
                                     struct vau_content_delete_record *out) {
    if (!j || !j->db || !out || !scope || scope > INT64_MAX)
        return VAU_INVALID;
    if (j->scope_active)
        return VAU_BUSY;
    char sql[512], id[24];
    int n = vau_snprintf(sql, sizeof(sql),
                         "SELECT %s FROM content_delete_events WHERE scope_sequence=?1 OR "
                         "requested_preview=?1 ORDER BY sequence LIMIT 1",
                         fields);
    if (n < 0 || (size_t)n >= sizeof(sql))
        return VAU_DEVICE_ERROR;
    vau_snprintf(id, sizeof(id), "%llu", (unsigned long long)scope);
    sqlite3_stmt *s = NULL;
    int rc = prepare(j->db, sql, &s);
    if (!rc)
        rc = error(sqlite3_bind_text(s, 1, id, -1, NULL));
    if (!rc) {
        int step = sqlite3_step(s);
        if (step == 101)
            rc = 1;
        else if (step == 100) {
            struct vau_content_audit_event event;
            rc = decode(s, &event);
            if (!rc)
                rc = bound_scope(j, &event.record);
            if (!rc)
                *out = event.record;
        } else
            rc = error(step);
    }
    if (s) {
        int end = error(sqlite3_finalize(s));
        if (!rc)
            rc = end;
    }
    return rc;
}
