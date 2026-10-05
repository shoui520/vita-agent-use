/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_APP_REGISTRY_H
#define VAU_APP_REGISTRY_H

#include <stdint.h>

#define VAU_APP_PAGE_ENTRIES 2u
#define VAU_APP_ID_BYTES     32u
#define VAU_APP_NAME_BYTES   384u
#define VAU_APP_QUERY_BYTES  128u

struct vau_app_entry {
	char title_id[VAU_APP_ID_BYTES], name[VAU_APP_NAME_BYTES], category[16];
};

struct vau_app_page {
	struct vau_app_entry entries[VAU_APP_PAGE_ENTRIES];

	uint32_t count, more;
	char next_after[VAU_APP_ID_BYTES];
};

/* The device adapter fixes the native registry path. Never exposed as SQL or a
 * caller-selected database path; each page is a fresh read-only observation. */
int vau_app_registry_read(const char *path, const char *after, const char *query,
                          struct vau_app_page *out);

/* Exact native registration lookup: 0 found, 1 absent, negative error.
 * Ambiguous duplicate metadata is an error, never evidence for deletion. */
int vau_app_registry_find(const char *path, const char *title, struct vau_app_entry *out);
#define VAU_APP_INSTALL_FIELDS      11u
#define VAU_APP_INSTALL_VALUE_BYTES 512u

struct vau_app_install_metadata {
	/* Values are native metadata, not necessarily absolute paths. A savedata
	 * or add-on directory ID still needs its native namespace resolved. */
	char values[VAU_APP_INSTALL_FIELDS][VAU_APP_INSTALL_VALUE_BYTES];
	char gamedata_id[VAU_APP_INSTALL_VALUE_BYTES];
	unsigned present;
};

const char *vau_app_install_field(unsigned);

/* Same tbl_appinfo values used by SceLsdb's title metadata query. Read only,
 * fixed key allowlist. 0 found, 1 no relevant rows, negative error. */
int vau_app_registry_install_metadata(const char *, const char *,
                                      struct vau_app_install_metadata *);

/* Native savedata-sharing predicate: another registered metadata title uses
 * the same INSTALL_DIR_SAVEDATA. Caller must check rc before using the flag. */
int vau_app_registry_savedata_shared(const char *, const char *, const char *, int *);

/* Native GAMEDATA_ID and another-title sharing predicate, in one read-only
 * statement. Empty output means no data ID; malformed/duplicate rows fail. */
int vau_app_registry_gamedata(const char *, const char *, char[VAU_APP_INSTALL_VALUE_BYTES], int *);
int vau_vita_app_list(void *context, const char *after, const char *query,
                      struct vau_app_page *out);

#endif
