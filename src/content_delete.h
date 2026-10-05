/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CONTENT_DELETE_H
#define VAU_CONTENT_DELETE_H

#include "acl_approval.h"
#include "app_registry.h"
#include "vita_agent.h"
#include "vita_agent_policy.h"
#include <stdint.h>

/* One durable, locally approved native content operation. Remote yes expresses
 * intent; only the adapter's native user decision authorizes the operation. */
enum vau_content_operation_kind {
	VAU_CONTENT_APPLICATION,
	VAU_CONTENT_VITA_SAVEDATA,
	VAU_CONTENT_PHOTO,
	VAU_CONTENT_MUSIC,
	VAU_CONTENT_VIDEO
};

struct vau_content_delete_request {
	char subject[65], id[33], title[10];
	unsigned yes;
	uint64_t preview_sequence;
	unsigned kind, user;
	uint64_t media_id; /* Positive native MRID for media; zero for apps/savedata. */
};

/*
 *   APPROVAL   durable record written; the native OK/Cancel prompt is showing
 *   RUNNING    persisted before the native delete starts (effect_started)
 *   COMPLETE   deleted, and confirmed by inspection afterwards
 *   DENIED     Cancel, a policy recheck failed, or approval was interrupted
 *   FAILED     refused before any effect (e.g. target changed since preview)
 *   UNCERTAIN  the delete may have happened but cannot be confirmed; also any
 *              RUNNING record found again after a reboot
 *
 * Path snapshots: PREVIEW is the plan the user reviews; BEFORE is taken after
 * the physical OK and must cover exactly the reviewed paths; AFTER is taken
 * once the native call finishes.
 */
enum vau_content_delete_state {
	VAU_CONTENT_DELETE_IDLE,
	VAU_CONTENT_DELETE_APPROVAL,
	VAU_CONTENT_DELETE_RUNNING,
	VAU_CONTENT_DELETE_COMPLETE,
	VAU_CONTENT_DELETE_DENIED,
	VAU_CONTENT_DELETE_FAILED,
	VAU_CONTENT_DELETE_UNCERTAIN
};

struct vau_content_observation {
	unsigned registered, application_present;
};

struct vau_content_delete_record {
	struct vau_content_delete_request request;

	enum vau_content_delete_state state;
	struct vau_content_observation before, after;
	unsigned after_known, effect_started;
	int result;
	uint64_t observed_us;
	uint64_t scope_sequence; /* Immutable affected-path snapshot; native-owned. */
};

struct vau_content_delete_adapter {
	void *context;

	uint64_t (*clock)(void *);

	/* 1 absent, 0 found, negative error. Persistent lookup binds the full request. */
	int (*lookup)(void *, const char *, const char *, struct vau_content_delete_record *);

	/* Flush before returning: no native operation without a durable anchor. */
	int (*persist)(void *, const struct vau_content_delete_record *);

	/* Validate native registry/title path and every applicable policy on each call. */
	int (*inspect)(void *, const struct vau_content_delete_request *,
	               struct vau_content_observation *);
	int (*allowed)(void *, const struct vau_content_delete_request *);

	/* Nonzero is allowed only when no dialog/callback ownership was acquired. */
	int (*approval_begin)(void *, const struct vau_content_delete_request *);

	/* BUSY while pending; 0 means physical OK, DENIED means Cancel. */
	int (*approval_poll)(void *);

	/* Release UI/input gate only after native callback ownership is finished. */
	int (*approval_finish)(void *);

	/* Nonblocking start/poll: blocking Sony SDK calls run on the native worker. */
	int (*native_start)(void *, const struct vau_content_delete_request *);
	int (*native_poll)(void *, int *);

	/* Required for savedata: verify committed affected-path outcomes after
	 * SDK completion and target inspection, before recording success. */
	int (*savedata_complete)(void *, const struct vau_content_delete_request *);
};

struct vau_content_delete {
	struct vau_content_delete_record record;
	int decision;
	unsigned decided, needs_persist;
};

void vau_content_delete_init(struct vau_content_delete *);
int vau_content_delete_request_valid(const struct vau_content_delete_request *);

/* Scope identity excludes the changing preview reference, but includes the
 * operation kind, numbered user, and native media ID. Zero-initialized existing callers are
 * application operations; their user must remain zero. */
int vau_content_delete_target_same(const struct vau_content_delete_request *,
                                   const struct vau_content_delete_request *);
int vau_content_delete_record_valid(const struct vau_content_delete_record *);
int vau_content_delete_submit(struct vau_content_delete *,
                              const struct vau_content_delete_adapter *,
                              const struct vau_content_delete_request *);
int vau_content_delete_poll(struct vau_content_delete *, const struct vau_content_delete_adapter *);

enum vau_content_path_role {
	VAU_CONTENT_ORIGIN,
	VAU_CONTENT_PATCH,
	VAU_CONTENT_LICENSE,
	VAU_CONTENT_SAVEDATA,
	VAU_CONTENT_SHARED_SAVEDATA,
	VAU_CONTENT_ADDCONT,
	VAU_CONTENT_ADDCONT_LICENSE,
	VAU_CONTENT_CACHE,
	VAU_CONTENT_APPMETA,
	VAU_CONTENT_WORK,
	VAU_CONTENT_BOOK,
	VAU_CONTENT_STAGING,
	VAU_CONTENT_GAMEDATA,
	VAU_CONTENT_SHARED_GAMEDATA,
	VAU_CONTENT_MEDIA_DATABASE,
	VAU_CONTENT_MEDIA_JOURNAL,
	VAU_CONTENT_MEDIA_FILE,
	VAU_CONTENT_MEDIA_RELATED,
	VAU_CONTENT_MEDIA_TEMP
};

/* Potential affected roots from the native backend, not a claim that a path
 * exists or will be removed. The native adapter observes each root, resolves
 * mounts, walks all existing descendants and evaluates policy before approval.
 * Shared saves are reported with an expected-preservation role, not deletion
 * authority. Policy still covers them: the native sharing check can fall back
 * to deleting saves on database failure. */
typedef int (*vau_content_path_visit)(void *, const char *, enum vau_content_path_role);

/* Writable Vita backend only. Other native backends need their own planners.
 * shared_savedata must be a successful native-registry sharing observation.
 * Fixed scratch memory, no allocation or truncation; visitor failure propagates. */
int vau_content_plan_vita(const char *, const struct vau_app_install_metadata *, int,
                          vau_content_path_visit, void *);

struct vau_legacy_install_metadata {
	char origin[VAU_APP_INSTALL_VALUE_BYTES];
	char gamedata_id[VAU_APP_INSTALL_VALUE_BYTES];
};

/* PSP/PlayStation application backend's _org_path and GAMEDATA_ID records.
 * Shared game data requires a successful native-registry sharing observation.
 * This plans roots only; it neither executes nor authorizes deletion. */
int vau_content_plan_legacy(const char *, const struct vau_legacy_install_metadata *, int,
                            vau_content_path_visit, void *);
int vau_content_plan_application(const char *, const struct vau_app_install_metadata *, int,
                                 vau_content_path_visit, void *);

/* A live savedata ID is a canonical single path component (1..255 bytes).
 * Only four uppercase letters followed by five digits are eligible for the
 * native backup helper. Valid other IDs have no backup-directory effect. */
int vau_content_savedata_id_valid(const char *);
int vau_content_savedata_backup_eligible(const char *);

/* Native backup matching uses directory order: stop at the first regular file
 * of exactly 31 bytes whose first nine bytes equal INSTALL_DIR_SAVEDATA.
 * name_bytes excludes the terminator; no suffix/date format is assumed.
 * Returns 1 for a match, 0 otherwise, or VAU_INVALID for invalid arguments. */
int vau_content_savedata_backup_match(const char *, const char *, size_t, int);

/* INTERNAL specified-user writable Vita savedata scope. backup is a bounded
 * selected filename (at most 31 bytes), or an empty string after a successful no-match
 * scan. The caller must obtain native metadata and fresh backup selection;
 * this neither scans, authorizes, nor executes deletion. */
int vau_content_plan_savedata(const char *, const struct vau_app_install_metadata *, unsigned,
                              const char *, vau_content_path_visit, void *);
const char *vau_content_path_role_name(enum vau_content_path_role);

typedef int (*vau_content_tree_visit)(void *, const char *);

struct vau_content_preflight_adapter {
	void *context;

	/* Read-only native walk: visit root and every existing descendant; reject
	 * links/aliases, verify mount identity; an absent root is successful. */
	int (*walk)(void *, const char *, vau_content_tree_visit, void *);
	int (*stopped)(void *);
};

/* Policy approval eligibility only; does not grant permission, open a dialog
 * or execute an SDK operation. Call again after physical OK with fresh native
 * metadata, sharing observation and policy snapshot. */
int vau_content_preflight_vita(const struct vau_file_policy *, const char *, int, const char *,
                               const struct vau_app_install_metadata *, int,
                               const struct vau_content_preflight_adapter *);

struct vau_content_approval {
	struct vau_acl_approval ui;
	uint64_t handle;
	int shared_savedata, legacy_application, finished;
};

void vau_content_approval_init(struct vau_content_approval *, struct vau_service *,
                               const struct vau_native_api *);

/* Adapter sets the trusted session handle and observed sharing flag before
 * begin. The request cannot supply its own identity, agent label or handle. */
int vau_content_approval_begin(void *, const struct vau_content_delete_request *);
int vau_content_approval_poll(void *);
int vau_content_approval_finish(void *);
void vau_content_approval_cancel(struct vau_content_approval *);

/* Deletion target and durable result serialization. */
int vau_content_record_json(const struct vau_content_delete_record *, int persisted, char *,
                            size_t);

/* Comma-prefixed target fields; empty for application JSON. */
int vau_content_target_json(const struct vau_content_delete_request *, char *, size_t);

#endif
