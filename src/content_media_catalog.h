/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CONTENT_MEDIA_CATALOG_H
#define VAU_CONTENT_MEDIA_CATALOG_H

#include "sqlite_api.h"
#include <stdint.h>

/* Internal read-only inspection of native photo/video album membership.
 * An association is a DB row, not a filesystem path or removal authorization.
 */
struct vau_content_media_link {
	uint64_t id, list_id;
	unsigned item_type;
};

typedef int (*vau_content_media_link_visit)(void *, const struct vau_content_media_link *);

/* Streams every association, without a fixed list limit. Callback storage is
 * borrowed. Caller owns the connection/transaction and must discard partial
 * observations if this returns an error, including finalize or cancellation. */
int vau_content_media_links(sqlite3 *, uint64_t, vau_content_media_link_visit, void *);

struct vau_content_media_list {
	uint64_t id, items, target_items;

	unsigned registered;
};

/* Always observes the requested list, including an absent registration and any
 * orphaned membership rows. The counts mirror native list_id counting, without
 * filtering item_type. Error clears output; registration is not completion. */
int vau_content_media_list(sqlite3 *, uint64_t, uint64_t, struct vau_content_media_list *);

struct vau_media_source {
	sqlite3 *db;

	unsigned category, transaction, ready;
};

/* Internal read-only connection, not the writable SceDbutil SDK owner. Zero
 * initialize before use; never copy live. Path is adapter-owned, never a peer
 * argument. Call record/album queries through this connection while its read
 * transaction is held. No SQL mutations or journal-mode overrides. */
int vau_media_source_open(struct vau_media_source *, const char *, unsigned);

/* Always attempts rollback and close, preserving the first cleanup error.
 * If close fails the handle remains owned here for cleanup retry; queries and
 * reopening are blocked. Do not discard a source with a retained DB handle. */
int vau_media_source_close(struct vau_media_source *);

/* Fixed native photo/music/video database paths; no source opened at startup.
 */
int vau_vita_media_source_open(struct vau_media_source *, unsigned);

/* Exact target identity from the native photo/music/video content database.
 * Native category1/2/3; status is observed, not interpreted as completion. */
struct vau_content_media_record {
	uint64_t id, bytes;

	unsigned category, status, bytes_known;
	char path[1024];
};

/* Internal metadata query. 0 found,1 absent,negative failure. Supplied
 * connection is caller-owned. No SQL mutation. Reject malformed/truncated
 * native path or ID/category mismatch. Failure publishes no partial record. */
int vau_content_media_record(sqlite3 *, unsigned, uint64_t, struct vau_content_media_record *);
int vau_vita_content_media_record(unsigned, uint64_t, struct vau_content_media_record *);
int vau_content_media_record_valid(const struct vau_content_media_record *);
int vau_content_media_record_same(const struct vau_content_media_record *,
                                  const struct vau_content_media_record *);

#endif
