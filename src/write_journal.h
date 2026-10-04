/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_WRITE_JOURNAL_H
#define VAU_WRITE_JOURNAL_H
#include "write_ops.h"
#include "sqlite_api.h"
#define VAU_AUDIT_PAGE_ENTRIES 2u
struct vau_write_journal { sqlite3 *db; };
struct vau_audit_page {
    struct vau_write_record records[VAU_AUDIT_PAGE_ENTRIES];
    unsigned count,more;
    uint64_t next_sequence;
};
/* Path is chosen by the trusted adapter, never remote JSON. SQLite rollback
 * transactions use DELETE journal/FULL sync. Filesystem-level durability must
 * still be verified on the native VFS; these settings alone are not proof. */
int vau_journal_open(struct vau_write_journal *,const char *);
/* Existing, initialized journal only; never creates a DB or writes events. */
int vau_journal_open_readonly(struct vau_write_journal *,const char *);
int vau_journal_close(struct vau_write_journal *);
int vau_journal_lookup(void *,const char *,const char *,struct vau_write_record *);
/* Includes PREPARE anchors used by uploads before the public path commit. */
int vau_journal_state(void *,const char *,const char *,struct vau_write_record *);
int vau_journal_append(void *,struct vau_write_record *);
/* pending_only enumerates unresolved INTENT/PREPARE records for native reconciliation.
 * Ordinary audit sync uses pending_only=0 and strictly increasing sequences. */
int vau_journal_page(struct vau_write_journal *,uint64_t,int,struct vau_audit_page *);
#endif
