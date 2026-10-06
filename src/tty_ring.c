/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "tty_ring.h"
#include <string.h>

int vau_tty_append(struct vau_tty_ring *ring, uint32_t source, int32_t pid, const void *data,
                   size_t length, uint64_t now)
{
	const unsigned char *bytes = data;

	if (!ring || (!data && length) || (source != VAU_TTY_KERNEL && source != VAU_TTY_USER))
		return VAU_INVALID;

	while (length) {
		VauTtyRecord *record =
		        ring->latest ? &ring->records[(ring->latest - 1) % VAU_TTY_RECORDS] : NULL;

		if (!record || ring->sealed == ring->latest || record->source != source ||
		    record->pid != pid || record->length == VAU_TTY_BYTES) {
			if (ring->latest == UINT32_MAX)
				return VAU_EXPIRED;

			record              = &ring->records[ring->latest++ % VAU_TTY_RECORDS];
			record->sequence    = ring->latest;
			record->source      = source;
			record->pid         = pid;
			record->observed_us = now;
			record->length      = 0;
			if (ring->count < VAU_TTY_RECORDS)
				ring->count++;
		}

		record->data[record->length++] = *bytes;
		if (*bytes++ == '\n')
			ring->sealed = ring->latest;
		length--;
	}

	return VAU_OK;
}

int vau_tty_read(struct vau_tty_ring *ring, uint32_t after, VauTtyPage *out)
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

	while (after < ring->latest && out->count < VAU_TTY_PAGE_RECORDS) {
		out->records[out->count++] = ring->records[after % VAU_TTY_RECORDS];
		out->next                  = ++after;
	}

	/* A copied record must never be extended behind the reader's cursor. */
	if (out->next == ring->latest)
		ring->sealed = ring->latest;
	out->more = after < ring->latest;
	return VAU_OK;
}
