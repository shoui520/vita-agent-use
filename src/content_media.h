/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CONTENT_MEDIA_H
#define VAU_CONTENT_MEDIA_H

#include "content_sdk.h"
#include "module_variable.h"
#include "vita_agent_policy.h"
#include <stddef.h>
#include <stdint.h>

/* Internal SceContentOperation ABI, verified against 3.65 native media callers.
 * The pointer fields are native-width; these structs are NOT wire messages. */
struct vau_media_sdk_owner {
	void *backend, *progress, *factories;
};

struct vau_media_sdk_ids {
	uint64_t *data;

	uint32_t count, capacity;
};

struct vau_media_sdk_string {
	const char *data;

	uint32_t bytes;
};

struct vau_media_sdk {
	struct vau_content_sdk_loader loader;

	void *memory_context;

	void *(*allocate)(void *, size_t);
	void (*release)(void *, void *);
	struct vau_media_sdk_owner *(*construct)(struct vau_media_sdk_owner *);
	struct vau_media_sdk_owner *(*destroy)(struct vau_media_sdk_owner *);
	int (*attach)(struct vau_media_sdk_owner *, void *, void *);
	int (*remove)(struct vau_media_sdk_owner *, struct vau_media_sdk_ids *,
	              const struct vau_media_sdk_string *, unsigned, const unsigned char *);

	unsigned bound, busy;
};

void vau_media_sdk_init(struct vau_media_sdk *, const struct vau_content_sdk_loader *, void *,
                        void *(*)(void *, size_t), void (*)(void *, void *));

/* Worker-only native primitive. category: photo=1/music=2/video=3. database
 * must be a live writable SceDbutil object, not a raw sqlite3 handle. The
 * caller owns its lifetime and media mounts. No authorization or completion
 * claim: full preview/physical approval/intent must precede this call; file,
 * database and related-path outcomes must be observed afterward even on native
 * failure. The resolver/allocator must belong to SceContentOperation/PAF. Not
 * exposed to protocol callers, and not automatically initialized at Shell
 * startup. */
int vau_media_sdk_remove(struct vau_media_sdk *, void *, unsigned, uint64_t);

/* Native 3.65 SceDbutil connection storage. Owned by this worker adapter;
 * never copy an initialized instance or substitute a sqlite3 pointer. */
union vau_media_db_storage {
	uint64_t alignment;

	unsigned char bytes[184];
};

struct vau_media_db {
	struct vau_content_sdk_loader loader;
	void *(*construct)(void *);
	void *(*destroy)(void *);
	int (*open)(void *, const struct vau_media_sdk_string *, uint32_t);
	int (*close)(void *);
	int (*timeout)(void *, int);

	union vau_media_db_storage storage;
	unsigned bound, constructed, ready, busy;
};

void vau_media_db_init(struct vau_media_db *, const struct vau_content_sdk_loader *);

/* Internal worker only. category photo1/music2/video3 selects a fixed native
 * database path. writable is0/1; writable open must follow approval/persisted
 * intent. File/mount authorization and native library lifetime are
 * caller-owned. No recovery/repair operation or raw SQL is dispatched here. */
int vau_media_db_open(struct vau_media_db *, unsigned, int);
void *vau_media_db_context(struct vau_media_db *);

/* Close only after all native operation/statement objects have been destroyed.
 * Always tears down this owned connection, preserving the native close error.
 * Native close clears its handle even on error; callers must not interpret an
 * error as a reusable connection or verified completion. */
int vau_media_db_close(struct vau_media_db *);
void vau_vita_media_db_init(struct vau_media_db *);

/* Internal PAF module references, never wire values. One serialized worker owns
 * this batch. Release only after SDK/profiler objects have been destroyed; any
 * cached exports from these modules must then be discarded before reuse. */
struct vau_media_modules {
	void *context;
	int (*resolve)(void *, uint32_t, uintptr_t *);
	int (*stopped)(void *);
	void **(*acquire)(void **, const char *, unsigned, unsigned, void *);
	void **(*release)(void **);
	int (*status)(void **);

	void *references[5];
	unsigned count, bound, busy;
};

void vau_media_modules_init(struct vau_media_modules *, void *,
                            int (*)(void *, uint32_t, uintptr_t *), int (*)(void *));

/* photo1/music2 acquire ContentOperation. video3 additionally acquires Marlin,
 * FflMp4, SenvuabsFFsdk and VideoProfiler in Sony's native worker order.
 * PAF and SceDbutil must already be resident; open the native DB context first.
 */
int vau_media_modules_acquire(struct vau_media_modules *, unsigned);
int vau_media_modules_release(struct vau_media_modules *);
void vau_vita_media_modules_init(struct vau_media_modules *, void *, int (*)(void *));

/* Worker-only native profiler enumeration. owner is an already opened native
 * profiler object, never a wire value. Its creation, parser setup, mounts and
 * destruction belong to the caller; one serialized worker owns this adapter.
 * Paths are callback-borrowed until return;
 * copy them into the durable preview before accepting a destructive request. */
struct vau_media_related {
	void *context;
	void (*release_path)(void *, void *);
	int (*stopped)(void *);

	unsigned busy;
};

typedef int (*vau_media_related_visit)(void *, const char *, size_t);
int vau_media_related_walk(struct vau_media_related *, void *, vau_media_related_visit, void *);

/* Internal worker adapter for the native SceVideoProfiler. Loader owns the
 * dependency modules/mounts. This adapter initializes the native default PAF
 * allocation context only if unset; it never replaces an existing context.
 * One serialized worker owns it. No raw DB pointer is passed to this API. */
struct vau_media_profiler {
	struct vau_content_sdk_loader loader;

	struct vau_media_related related;

	void *(*memory)(void);
	int (*initialize_memory)(void *);
	int (*open)(void *, const char *, void **, unsigned char);
	int (*close)(void *, void *);

	unsigned bound, busy;
};

void vau_media_profiler_init(struct vau_media_profiler *, const struct vau_content_sdk_loader *,
                             void *, void (*)(void *, void *), int (*)(void *));

/* Bind and initialize the default allocation context before a native video
 * deletion call, even when related-file enumeration is not invoked first. */
int vau_media_profiler_prepare(struct vau_media_profiler *);

/* path must be the native-resolved media path, with any required loopback mount
 * already held. Visits related files only; caller separately captures main file
 * and DB effects. No mutation, authorization or completion claim. */
int vau_media_profiler_walk(struct vau_media_profiler *, const char *, vau_media_related_visit,
                            void *);

/* Internal, serialized worker-owned mount of native AppData type105 (music0:).
 * Already-mounted status borrows the existing mount; only newly acquired mounts
 * are unmounted. Failed unmount retains ownership for explicit retry. */
struct vau_media_music {
	void *context;
	int (*mount)(void *, int, char *);
	int (*unmount)(void *, const char *);

	char point[16];
	unsigned active, owned, busy;
};

void vau_media_music_init(struct vau_media_music *, void *, int (*)(void *, int, char *),
                          int (*)(void *, const char *));
int vau_media_music_open(struct vau_media_music *);
int vau_media_music_close(struct vau_media_music *);
void vau_vita_media_music_init(struct vau_media_music *);

/* Internal worker-owned native video loopback (type600). Caller must hold the
 * native video dependencies during open/profiling; close uses resident AppMgr.
 * The resolved path is borrowed for the
 * lifetime of the mount; it is not a physical policy/audit path by itself. */
struct vau_media_loopback {
	void *context;
	int (*drm_context)(void *, char *);
	int (*mount)(void *, int, const char *, char *);
	int (*unmount)(void *, const char *);

	char point[16], path[1024];
	unsigned active, owned, busy;
};

void vau_media_loopback_init(struct vau_media_loopback *, void *, int (*)(void *, char *),
                             int (*)(void *, int, const char *, char *),
                             int (*)(void *, const char *));
int vau_media_loopback_open(struct vau_media_loopback *, const char *);
const char *vau_media_loopback_path(const struct vau_media_loopback *);
int vau_media_loopback_close(struct vau_media_loopback *);
void vau_vita_media_loopback_init(struct vau_media_loopback *);

/* Native GetRawPath uses a 292-byte input/output limit on 3.65. Keep both names
 * for the preview/audit: source metadata path and canonical native backing
 * path. Resolving does not authorize any operation or prove file
 * content/existence. */
struct vau_content_media_path {
	char logical[VAU_PATH_MAX], physical[VAU_PATH_MAX];
};

/* Exact music-path rewrite used by the native item worker (3.65 810031e4).
 * Other categories and nonmatching prefixes are copied unchanged. No filesystem
 * lookup or mutation. Output must be separate scratch storage. Caller must hold
 * the native music mount when resolving. */
int vau_content_media_operation_path(unsigned, const char *, char *, size_t);
int vau_content_media_path_resolve(void *, int (*)(void *, char *, char *, int), const char *,
                                   struct vau_content_media_path *);
int vau_vita_content_media_path(const char *, struct vau_content_media_path *);

struct vau_media_session;

struct vau_media_temp_directory {
	char path[257]; /* Native VSH temporary directory string, never truncated. */
	unsigned overridden;
};

/* Read the VSH normal data export BDCB4423; never modify the native global.
 * This is a metadata snapshot, not a mount grant or full effect-scope proof. */
int vau_media_temp_directory_read(void *, vau_memory_read, uintptr_t, uintptr_t,
                                  struct vau_media_temp_directory *);
int vau_vita_media_temp_directory(struct vau_media_session *, struct vau_media_temp_directory *);

struct vau_media_session_backend {
	struct vau_content_sdk_loader database, operation, profiler;

	void *context;

	int (*module_resolve)(void *, uint32_t, uintptr_t *);
	int (*prepare_memory)(void *);
	int (*mount_begin)(void *, unsigned);
	int (*mount_end)(void *);
	int (*path_begin)(void *, const char *, const char **);
	int (*path_end)(void *);
	int (*resolve_path)(void *, const char *, struct vau_content_media_path *);
	void *(*allocate)(void *, size_t);
	void (*release)(void *, void *);
	int (*stopped)(void *);
};

/* Internal worker ownership, not a protocol object. Native-resolved mounts and
 * durable approved effect scopes are caller-owned. One serialized worker owns
 * the session. Initialize only a fresh/inactive instance; never copy it live. */
struct vau_media_session {
	struct vau_media_session_backend backend;
	struct vau_media_db database;
	struct vau_media_modules modules;
	struct vau_media_sdk operation;
	struct vau_media_profiler profiler;
	unsigned category, writable, ready, busy, mount_active, path_active;
};

void vau_media_session_init(struct vau_media_session *, const struct vau_media_session_backend *);
int vau_media_session_open(struct vau_media_session *, unsigned, int);
int vau_media_session_related(struct vau_media_session *, const char *, vau_media_related_visit,
                              void *);

/* Photo/music main file, or video main plus every native profiler-associated file. The logical name
 * is the mounted name; preserve the source DB record separately. Both names are
 * borrowed until the callback returns. Copy observations into the preview and
 * commit only after the complete call succeeds, including mount cleanup.
 * No mutation, authorization, or completion claim. */
typedef int (*vau_media_path_visit)(void *, const struct vau_content_media_path *, unsigned);
int vau_media_session_paths(struct vau_media_session *, const char *, vau_media_path_visit, void *);

/* Compatibility entry requiring a video session. */
int vau_media_session_video_paths(struct vau_media_session *, const char *, vau_media_path_visit,
                                  void *);

/* Internal destructive primitive: caller must approve/persist full scope before
 * opening writable or invoking remove. Native acknowledgement is not completion. */
int vau_media_session_remove(struct vau_media_session *, uint64_t);
int vau_media_session_close(struct vau_media_session *);

struct vau_media_session_vita {
	struct vau_media_session session;

	struct vau_media_music music;
	struct vau_media_loopback loopback;
	void *stop_context;

	int (*stopped)(void *);
	void *(*allocate)(size_t);
	void (*release)(void *);
};

void vau_vita_media_session_init(struct vau_media_session_vita *, void *, int (*)(void *));

#endif
