/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "event_ring.h"
#include <string.h>

/*
 * The hooks see every file SceCoredump opens or renames. Only the dump file
 * itself (directly in ux0:data/, exact suffix, no separators) becomes an
 * event, which also makes its path safe to forward to clients unchanged.
 */
int vau_dump_path(const char *path, unsigned kind)
{
	if (!path || (kind != VAU_DUMP_SAVING && kind != VAU_DUMP_COMPLETE))
		return 0;

	size_t length = 0;

	while (length < VAU_DUMP_PATH_BYTES && path[length])
		++length;

	const char *suffix = kind == VAU_DUMP_SAVING ? ".psp2dmp.tmp" : ".psp2dmp";
	size_t tail        = strlen(suffix);

	return length < VAU_DUMP_PATH_BYTES && length > 9 + tail && !memcmp(path, "ux0:data/", 9) &&
	       !strchr(path + 9, '/') && !strchr(path + 9, ':') && !strchr(path, '\\') &&
	       !memcmp(path + length - tail, suffix, tail);
}

int vau_event_publish(struct vau_event_ring *ring, unsigned kind, const char *path, uint64_t now)
{
	if (!ring || !vau_dump_path(path, kind))
		return VAU_INVALID;
	if (ring->latest == UINT32_MAX)
		return VAU_EXPIRED;

	uint32_t seq    = ++ring->latest;
	VauDumpEvent *e = &ring->events[(seq - 1) % VAU_EVENT_RING_COUNT];

	memset(e, 0, sizeof(*e));
	e->sequence    = seq;
	e->kind        = kind;
	e->observed_us = now;
	memcpy(e->path, path, strlen(path) + 1);
	if (ring->count < VAU_EVENT_RING_COUNT)
		++ring->count;
	return VAU_OK;
}

int vau_event_read(const struct vau_event_ring *ring, uint32_t after, VauDumpPage *out)
{
	if (!ring || !out || after > ring->latest)
		return VAU_STALE;

	memset(out, 0, sizeof(*out));
	out->size   = sizeof(*out);
	out->abi    = VAU_ABI;
	out->latest = ring->latest;
	out->next   = after;

	uint32_t first = ring->latest - ring->count;

	if (after < first) {
		out->lost = first - after;
		after     = first;
		out->next = first;
	}

	while (after < ring->latest && out->count < VAU_EVENT_PAGE_COUNT) {
		out->events[out->count++] = ring->events[after % VAU_EVENT_RING_COUNT];
		out->next                 = ++after;
	}

	out->more = after < ring->latest;
	return VAU_OK;
}
