/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_CONTENT_JOURNAL_H
#define VAU_CONTENT_JOURNAL_H
#include "content_delete.h"
#include "sqlite_api.h"
struct vau_content_journal {
    sqlite3 *db;
    uint64_t scope_active;
};
struct vau_content_audit_event {
    uint64_t sequence;
    struct vau_content_delete_record record;
};
struct vau_content_audit_page {
    struct vau_content_audit_event events[2];
    unsigned count, more;
    uint64_t next;
};
/* Adapter-owned path, never a peer-supplied SQLite file or SQL statement. */
int vau_content_journal_open(struct vau_content_journal *, const char *, int readonly);
int vau_content_journal_close(struct vau_content_journal *);
int vau_content_journal_lookup(void *, const char *, const char *, struct vau_content_delete_record *);
int vau_content_journal_persist(void *, const struct vau_content_delete_record *);
int vau_content_journal_persist_scope(struct vau_content_journal *, const struct vau_content_delete_record *,
                                      uint64_t);
int vau_content_journal_scope_lookup(struct vau_content_journal *, uint64_t,
                                     struct vau_content_delete_record *);
int vau_content_journal_page(struct vau_content_journal *, uint64_t, struct vau_content_audit_page *);
#endif
