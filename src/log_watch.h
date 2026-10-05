/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_LOG_WATCH_H
#define VAU_LOG_WATCH_H

#include "log_marker.h"
#include "file_ops.h"

#define VAU_LOG_WATCHES     4u
#define VAU_LOG_CHUNK       768u
#define VAU_LOG_GUARD_BYTES 64u

struct vau_log_watch_slot {
	char owner[65], path[VAU_PATH_MAX];
	struct vau_log_marker marker;
	uint32_t id;
	unsigned char guard[VAU_LOG_GUARD_BYTES];
	uint32_t guard_bytes;
};

struct vau_log_watches {
	struct vau_log_watch_slot slots[VAU_LOG_WATCHES];

	uint32_t next;
};

/* Native live-tail adapter: append during read is permitted. Returns current
 * bytes available and reset on observable truncation/replacement. The guard
 * contains the previously observed bytes immediately preceding the offset;
 * compare it using the same opened file before reading the next chunk. */
typedef int (*vau_log_tail_fn)(void *, const char *, uint64_t, const void *, uint32_t, void *,
                               uint32_t, uint32_t *, uint64_t *, int *);
int vau_log_watch(struct vau_log_watches *, vau_file_stat_fn, vau_log_tail_fn, void *, const char *,
                  uint32_t, const char *, const char *, uint32_t, char *, size_t);
int vau_vita_log_watch(void *, const char *, uint32_t, const char *, const char *, uint32_t, char *,
                       size_t);

#endif
