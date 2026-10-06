/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef VAU_TTY_RING_H
#define VAU_TTY_RING_H

#include "vau_tty.h"
#include <stddef.h>

/* Caller serializes access. Partial lines are delivered without waiting for '\n'. */
struct vau_tty_ring {
	uint32_t latest, count, sealed;
	VauTtyRecord records[VAU_TTY_RECORDS];
};

int vau_tty_append(struct vau_tty_ring *, uint32_t, int32_t, const void *, size_t, uint64_t);
int vau_tty_read(struct vau_tty_ring *, uint32_t, VauTtyPage *);

#endif
