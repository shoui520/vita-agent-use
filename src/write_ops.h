/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_WRITE_OPS_H
#define VAU_WRITE_OPS_H

#include "vita_agent_policy.h"
#include "vita_agent.h"
#include <stdint.h>

/* Native coordinator contract. No public endpoint may call raw mutation I/O.
 * Each id is a fresh 128-bit host operation identity, replayed unchanged after
 * response loss. Journal lookup must bind the entire normalized request. */
struct vau_write_request {
	char id[33], subject[65], path[VAU_PATH_MAX], destination[VAU_PATH_MAX];
	char trash_id[33]; /* PURGE provenance: completed trash operation for this peer. */
	enum vau_file_operation operation;
	unsigned yes, recursive, overwrite;
	uint64_t bytes;
	char sha256[65], expected_sha256[65]; /* Upload digest; optional old-file precondition (required
	                                         for tai config). */
};

enum vau_write_phase {
	VAU_WRITE_INTENT,
	VAU_WRITE_COMPLETE,
	VAU_WRITE_PROGRESS,
	VAU_WRITE_PREPARE
};

enum vau_write_state {
	VAU_STATE_UNKNOWN   = 0,
	VAU_STATE_MISSING   = 1,
	VAU_STATE_OTHER     = 3,
	VAU_STATE_FILE      = 7,
	VAU_STATE_DIRECTORY = 11
};

struct vau_write_observation {
	unsigned state;
	uint64_t bytes;
};

struct vau_write_record {
	struct vau_write_request request;

	uint64_t sequence;
	enum vau_write_phase phase;
	int result;
	unsigned effect_started, readback_required;
	uint64_t observed_us, offset;
	char detail[32];                /* Native substep label, never arbitrary peer text. */
	char detail_path[VAU_PATH_MAX]; /* Logical affected path for per-child audit. */
	char effect_path[VAU_PATH_MAX]; /* Actual destination or trash path affected. */
	struct vau_write_observation before, after, destination_before, destination_after;
};

typedef int (*vau_write_visit)(void *, const char *);

struct vau_write_adapter {
	void *context;

	/* Return 1 when absent, 0 when found, a negative error otherwise. */
	int (*lookup)(void *, const char *, const char *, struct vau_write_record *);

	/* Persist and flush the record before returning success. Allocate a
	 * monotonic sequence on device; never accept a sequence from the peer. */
	int (*audit)(void *, struct vau_write_record *);

	/* Native stat/link/mount checks, then recursively visit ALL descendants
	 * without modifying them. Directory modifications require full preflight. */
	int (*preflight)(void *, const struct vau_write_request *, vau_write_visit, void *);

	/* Reject absent/invalid recovery proof and preserve protected config.
	 * Required for config commits; run both device and client checks. */
	int (*config_check)(void *, const struct vau_write_request *);

	/* Adapter stages/backs up/rechecks before mutation, and journals substeps
	 * for reboot recovery. Output flags remain truthful on partial failure. */
	int (*apply)(void *, const struct vau_write_request *, unsigned *, unsigned *);
	int (*stopped)(void *);
};

int vau_write_request_same(const struct vau_write_request *, const struct vau_write_request *);
int vau_write_execute(const struct vau_file_policy *, const struct vau_write_adapter *,
                      const struct vau_write_request *, struct vau_write_record *);
int vau_write_changes_json(const struct vau_write_record *, char *, size_t);

#endif
