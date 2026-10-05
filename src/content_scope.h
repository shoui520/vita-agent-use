/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CONTENT_SCOPE_H
#define VAU_CONTENT_SCOPE_H

#include "content_delete.h"
#include "content_journal.h"
#include "content_media_catalog.h"
#include "file_ops.h"
#include "write_ops.h"

enum vau_content_scope_phase {
	VAU_CONTENT_SCOPE_PREVIEW,
	VAU_CONTENT_SCOPE_BEFORE,
	VAU_CONTENT_SCOPE_AFTER
};

struct vau_content_path_observation {
	unsigned state; /* VAU_STATE_*; unknown preserves the native error. */
	int error;
	struct vau_file_info info;
};

struct vau_content_scope {
	uint64_t sequence, observed_us, path_count;

	struct vau_content_delete_request request;
	enum vau_content_scope_phase phase;
};

struct vau_content_scope_writer {
	struct vau_content_journal *journal;

	struct vau_content_scope scope;
	uint64_t roots;
	int failure;
	unsigned media_added, albums_started, albums_finished;
};

struct vau_content_scope_path {
	uint64_t sequence;

	char path[VAU_PATH_MAX];
	enum vau_content_path_role role;
	unsigned root;
	struct vau_content_path_observation observation;
};

struct vau_content_scope_page {
	struct vau_content_scope_path entries[2];

	unsigned count, more;
	uint64_t next;
};

/* Zero-initialize the writer before first use. SQLite streams paths to disk
 * with fixed scratch memory. A scope is visible only after its FULL-sync
 * commit. Abort on any preflight error. */
int vau_content_scope_begin(struct vau_content_scope_writer *, struct vau_content_journal *,
                            const struct vau_content_delete_request *, enum vau_content_scope_phase,
                            uint64_t);
int vau_content_scope_add(struct vau_content_scope_writer *, const char *,
                          enum vau_content_path_role, unsigned,
                          const struct vau_content_path_observation *);
int vau_content_scope_commit(struct vau_content_scope_writer *);
int vau_content_scope_abort(struct vau_content_scope_writer *);

enum vau_content_media_state {
	VAU_MEDIA_UNKNOWN,
	VAU_MEDIA_ABSENT,
	VAU_MEDIA_PRESENT
};

struct vau_content_media_observation {
	unsigned state;
	int error;
	struct vau_content_media_record record;
};

/* Exactly one native record observation per media scope, in the same FULL-sync
 * transaction as affected files. PREVIEW/BEFORE require PRESENT; AFTER may
 * preserve absence or native query failure without implying completion. */
int vau_content_scope_media_add(struct vau_content_scope_writer *,
                                const struct vau_content_media_observation *);
int vau_content_scope_media_get(struct vau_content_journal *, uint64_t,
                                struct vau_content_media_observation *);

struct vau_content_album_set {
	uint64_t links, lists;
};

/* Native membership rows share the source/path transaction. Finish even an
 * empty enumeration; absent set means unobserved. Every linked list must have
 * one observation. No native effects or completion/authorization inference. */
int vau_content_scope_album_link_add(struct vau_content_scope_writer *,
                                     const struct vau_content_media_link *);
int vau_content_scope_album_list_add(struct vau_content_scope_writer *,
                                     const struct vau_content_media_list *);
int vau_content_scope_albums_finish(struct vau_content_scope_writer *);
int vau_content_scope_albums_get(struct vau_content_journal *, uint64_t,
                                 struct vau_content_album_set *);

/* Bounded transport reader over immutable journal rowids. Independent cursors
 * cover links and lists, including native list_id zero. No OFFSET rescanning. */
#define VAU_CONTENT_ALBUM_PAGE_ROWS 8u

struct vau_content_album_page {
	struct vau_content_album_set set;
	struct vau_content_media_link links[VAU_CONTENT_ALBUM_PAGE_ROWS];
	struct vau_content_media_list lists[VAU_CONTENT_ALBUM_PAGE_ROWS];
	uint64_t next_link, next_list;
	unsigned known, link_count, list_count, more;
};

int vau_content_scope_albums_page(struct vau_content_journal *, uint64_t, uint64_t, uint64_t,
                                  struct vau_content_album_page *);

struct vau_content_album_entry {
	unsigned is_list;

	struct vau_content_media_link link;
	struct vau_content_media_list list;
};

typedef int (*vau_content_album_visit)(void *, const struct vau_content_album_entry *);

/* Streams committed links and list observations. Callback data is borrowed;
 * discard partial output on any error. Absent enumeration returns1. */
int vau_content_scope_albums_visit(struct vau_content_journal *, uint64_t, vau_content_album_visit,
                                   void *);
int vau_content_scope_source_albums_visit(struct vau_content_scope_writer *, uint64_t,
                                          vau_content_album_visit, void *);

/* Current writer's internal de-duplication lookup: 0 missing,1 observed,negative error. */
int vau_content_scope_album_list_seen(struct vau_content_scope_writer *, uint64_t);

/* Committed immutable snapshots. Before native execution use BEFORE, not the
 * earlier UI preview; after execution observe these saved paths even if native
 * application metadata has disappeared. Never re-run an operation to observe. */
int vau_content_scope_latest(struct vau_content_journal *,
                             const struct vau_content_delete_request *,
                             enum vau_content_scope_phase, struct vau_content_scope *);
int vau_content_scope_get(struct vau_content_journal *, uint64_t, struct vau_content_scope *);
int vau_content_scope_find(struct vau_content_journal *, uint64_t, const char *,
                           struct vau_content_scope_path *);
int vau_content_scope_page(struct vau_content_journal *, uint64_t, uint64_t,
                           struct vau_content_scope_page *);

/* Owner-only reader for a committed BEFORE snapshot while collecting AFTER. */
int vau_content_scope_source_page(struct vau_content_scope_writer *, uint64_t, uint64_t,
                                  struct vau_content_scope_page *);
int vau_content_path_observation_valid(const struct vau_content_path_observation *);

/* Internal savedata outcome verification against committed BEFORE/AFTER
 * scopes. Every reviewed path must be observed after; live/backup paths and
 * staging contents must be gone. The shared staging root may remain empty.
 * Original native observation errors propagate; this never executes effects. */
int vau_content_scope_savedata_complete(struct vau_content_journal *, uint64_t, uint64_t);

/* Internal media outcome predicate over committed BEFORE/AFTER evidence.
 * Requires source/files/memberships gone, database preserved and known temp
 * paths accounted for. No SDK effect, permission or full side-effect proof. */
int vau_content_scope_media_complete(struct vau_content_journal *, uint64_t, uint64_t);

/* NULL on either side means unobserved, never inferred deletion/creation.
 * Every emitted path is full length. Metadata equality is not a content hash. */
int vau_content_scope_changes_json(const struct vau_content_scope_path *,
                                   const struct vau_content_scope_path *, char *, size_t);

/* Bound immutable snapshots. AFTER=0 means unobserved. Transport pages are
 * fixed scratch memory; the host assembles all paths by default. */
int vau_content_changes_json(struct vau_content_journal *,
                             const struct vau_content_delete_request *, uint64_t before,
                             uint64_t after, uint64_t cursor, char *, size_t);
int vau_content_audit_json(struct vau_content_journal *, uint64_t cursor, char *, size_t);

/* Media scopes additionally report source_observation and album_observation
 * counts. Unobserved albums never imply an empty set. Status is raw native
 * metadata, not a completion claim. Oversized output fails without truncation. */
int vau_content_snapshot_json(struct vau_content_journal *,
                              const struct vau_content_delete_request *, uint64_t scope,
                              uint64_t cursor, char *, size_t);
int vau_content_albums_json(struct vau_content_journal *, const struct vau_content_delete_request *,
                            uint64_t, uint64_t, uint64_t, char *, size_t);

#endif
