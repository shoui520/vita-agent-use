/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "service.h"

static int status(void *context, VauStopStatus *out)
{
	(void)context;
	return vauInputGetStopStatus(out);
}

static int rearm(void *context, uint64_t generation)
{
	(void)context;
	return vauInputRearm(generation);
}
const struct vau_stop_bridge vau_vita_stop_bridge = { NULL, status, rearm };
