/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CONTENT_SDK_H
#define VAU_CONTENT_SDK_H

#include <stdint.h>
#include "vita_agent.h"
#include <stdatomic.h>
#include "file_ops.h"

/* Resolved lazily on the native content worker, never at Shell boot. One
 * serialized owner retains these process-wide module bindings for its life. */
struct vau_content_sdk_loader {
	void *context;

	/* 0 = already loaded, 1 = must call load() first, < 0 = error. */
	int (*loaded)(void *);
	int (*load)(void *);

	/* Resolves an export NID inside the loaded module; 0 with *out == 0 is a miss. */
	int (*resolve)(void *, uint32_t, uintptr_t *);
};

struct vau_content_sdk {
	struct vau_content_sdk_loader loader;

	int (*initialize)(void);
	int (*state)(int *);
	int (*delete_package)(const char *);
	int (*remove_savedata)(const char *, int, int);
	int (*promote_package)(const char *, int);

	unsigned bound, initialized;
};

void vau_content_sdk_init(struct vau_content_sdk *, const struct vau_content_sdk_loader *);

/* Internal worker callback, not authorization. Caller must have persisted the
 * full scope and obtained the physical decision before scheduling this call. */
int vau_content_sdk_delete(void *, const char *);
int vau_content_sdk_promote(struct vau_content_sdk *, const char *);

/* Internal specified-user native savedata primitive. Caller must bind a
 * reviewed registered title/user scope, persist intent and obtain physical OK.
 * This is not an arbitrary PSP savedata directory-removal API. */
int vau_content_sdk_remove_savedata(struct vau_content_sdk *, const char *, unsigned);
void vau_vita_content_sdk_init(struct vau_content_sdk *);

#define VAU_CONTENT_WORKER_STACK 16384u

struct vau_content_worker {
	int thread, started, result;
	atomic_uint done;

	int (*execute)(void *, const char *);

	void *context;
	char title[10];
};

/* Owner is the command thread. Storage and callback code remain resident until
 * poll acknowledges thread exit and deletes the thread. SDK operations are
 * never killed on timeout: killing one cannot undo its native side effects. */
void vau_content_worker_init(struct vau_content_worker *);
int vau_content_worker_start(struct vau_content_worker *, const char *,
                             int (*)(void *, const char *), void *);
int vau_content_worker_poll(struct vau_content_worker *, int *);

/* Read-only native-directory-order selection, matching Shell's backup finder.
 * Empty filename on successful return means no backup matched, not an error.
 * No heap allocation, file contents, sorting, or global descriptor ownership.
 * The caller supplies cancellation; never scan from input/display hooks.
 * Re-scan before execution; metadata is an observation, not a lock. */
struct vau_savedata_backup {
	char filename[32];

	unsigned directory_present, found;
	uint64_t entries_read;
	struct vau_file_info directory, file;
};

int vau_vita_savedata_backup(unsigned, const char *, int (*)(void *), void *,
                             struct vau_savedata_backup *);

#endif
