/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CONTENT_CAPTURE_H
#define VAU_CONTENT_CAPTURE_H

#include "content_media.h"
#include "content_media_catalog.h"
#include "content_scope.h"

typedef int (*vau_content_capture_visit)(void *, const char *,
                                         const struct vau_content_path_observation *);

struct vau_content_capture_adapter {
	void *context;

	/* Missing is a successful MISSING observation; other stat errors are
	 * successful UNKNOWN observations containing the original native error. */
	int (*observe)(void *, const char *, struct vau_content_path_observation *);

	/* Read-only, canonical paths, no links. Includes root. Mount identity
	 * must be validated by the native operation adapter before execution. */
	int (*walk)(void *, const char *, vau_content_capture_visit, void *);
	int (*stopped)(void *);
};

/* Vita and PSP/PlayStation application backends selected by native origin.
 * Writer must already own its transaction. Failure poisons it: caller aborts.
 * BEFORE/PREVIEW check policy on every potential root and existing descendant. */
int vau_content_capture_vita(struct vau_content_scope_writer *, const struct vau_file_policy *,
                             const struct vau_app_install_metadata *, int,
                             const struct vau_content_capture_adapter *);

/* Internal specified-user savedata capture. Native backup selection must be
 * refreshed before BEFORE capture; approval/execution is a separate workflow. */
int vau_content_capture_savedata(struct vau_content_scope_writer *, const struct vau_file_policy *,
                                 const struct vau_app_install_metadata *, unsigned, const char *,
                                 const struct vau_content_capture_adapter *);

/* Internal media PREVIEW/BEFORE collection using a ready read-only native
 * session and exact source record. Streams physical main/associated paths and
 * fixed native database/rollback-journal observations into the same transaction.
 * Close the session successfully before committing the writer. Unknown native
 * database side effects still need verification before exposing deletion. */
int vau_content_capture_media(struct vau_content_scope_writer *, const struct vau_file_policy *,
                              struct vau_media_session *, const struct vau_content_media_record *,
                              const struct vau_content_capture_adapter *);

/* Snapshot the native temporary directory and existing descendants. Its root
 * must be a direct canonical partition path after normalization, directory or
 * absent. Every potential write/removal path is policy checked. Never creates,
 * deletes, changes the SQLite global or authorizes native execution. */
int vau_content_capture_media_temp(struct vau_content_scope_writer *,
                                   const struct vau_file_policy *,
                                   const struct vau_media_temp_directory *,
                                   const struct vau_content_capture_adapter *);

/* Read-only album collection. Source SQLite connection must be held in a
 * consistent read transaction with the source-record observation. BEFORE/PREVIEW
 * use before=0. AFTER re-observes every saved BEFORE list, including lists whose
 * links disappeared. This captures metadata only and never executes deletion. */
int vau_content_capture_media_albums(struct vau_content_scope_writer *, struct vau_media_source *,
                                     uint64_t, const struct vau_content_capture_adapter *);

/* Combined record/files/album snapshot. PREVIEW/BEFORE uses before0 and a
 * ready read-only native path session. AFTER re-observes saved paths/lists and
 * stores ABSENT/PRESENT/UNKNOWN source state; session/policy are not needed.
 * Source/session cleanup must succeed before committing. This is observation,
 * not full temporary-effect coverage or permission to execute deletion. */
int vau_content_capture_media_view(struct vau_content_scope_writer *,
                                   const struct vau_file_policy *, struct vau_media_session *,
                                   struct vau_media_source *, uint64_t,
                                   const struct vau_content_capture_adapter *);

/* AFTER fallback when the source DB cannot be opened. Persist UNKNOWN with
 * original negative error and observe saved paths. Album enumeration remains
 * unobserved; this never infers an empty set or successful deletion. */
int vau_content_capture_media_unavailable(struct vau_content_scope_writer *, uint64_t, int,
                                          const struct vau_content_capture_adapter *);

/* Observe original BEFORE paths without consulting deleted registry metadata.
 * Also walk surviving roots to include new descendants. Auth disconnect does
 * not stop this internal audit after an SDK effect has started. */
int vau_content_capture_after(struct vau_content_scope_writer *, uint64_t,
                              const struct vau_content_capture_adapter *);

/* Native read-only adapter. stop_context stays valid for the whole capture.
 * AFTER uses a separate adapter with no cancellation callback, so a revoked
 * session cannot prevent observation of an already-started SDK effect. */
struct vau_content_capture_native {
	int (*stopped)(void *);

	void *stop_context;
};

void vau_content_capture_native_adapter(struct vau_content_capture_adapter *,
                                        struct vau_content_capture_native *);

#endif
