/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_PERFORMANCE_H
#define VAU_PERFORMANCE_H

#include <stdint.h>
#include "vita_agent.h"

/* Raw counters; conversion uses actual monotonic windows, never network time. */
typedef struct {
	uint32_t size, abi;
	int32_t pid, foreground_error, fps_error, memory_error;
	uint32_t frames, plane;
	char title[12];
	uint32_t total[4], free[4]; /* USER_RW, CDRAM, PHYCONT, CDLG */
} VauPerformanceRaw;

int vau_performance_kernel(uint32_t enabled, VauPerformanceRaw *out);
int vauPerformanceRead(uint32_t enabled, VauPerformanceRaw *out);

#endif
