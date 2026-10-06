/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_DECRYPT_H
#define VAU_DECRYPT_H

#include "vita_agent.h"

#define VAU_DECRYPT_BLOCK  65536u
#define VAU_DECRYPT_HEADER 4096u

enum {
	VAU_DECRYPT_OPEN,
	VAU_DECRYPT_SEGMENT,
	VAU_DECRYPT_BLOCK_OP,
	VAU_DECRYPT_FINISH
};

typedef struct {
	uint32_t size, operation, length, segment, self_type;
	char path[512], rif[512];
} VauDecryptRequest;

/* Shell-only bridge. License material never leaves the kernel. */
int vauDecryptSelf(const VauDecryptRequest *, void *);
int vau_decrypt_kernel(const VauDecryptRequest *, void *);
#endif
