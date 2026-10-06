/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef VAU_TTY_H
#define VAU_TTY_H

#include "vita_agent.h"

#define VAU_TTY_BYTES        256u
#define VAU_TTY_RECORDS      32u
#define VAU_TTY_PAGE_RECORDS 4u

enum {
	VAU_TTY_KERNEL = 1,
	VAU_TTY_USER   = 2
};

typedef struct {
	uint64_t observed_us;
	uint32_t sequence, source;
	int32_t pid;
	uint32_t length;
	unsigned char data[VAU_TTY_BYTES];
} VauTtyRecord;

typedef struct {
	uint32_t size, abi, next, latest, count, more, lost, dropped;
	int32_t kernel_error, user_error;
	VauTtyRecord records[VAU_TTY_PAGE_RECORDS];
} VauTtyPage;

int vauTtyRead(uint32_t operation, uint32_t after, VauTtyPage *out);
int vau_tty_kernel(uint32_t operation, uint32_t after, VauTtyPage *out);

#endif
