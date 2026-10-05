/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CAPTURE_KERNEL_H
#define VAU_CAPTURE_KERNEL_H

#include "vita_agent.h"

/* Caller has entered syscall and checked Shell identity. Does not acquire the
 * input scheduler mutex or wait for VBlank. Only one capture may run at once. */
int vau_capture_kernel(void *user_pixels, uint32_t capacity, VauFrameInfo *info);

#endif
