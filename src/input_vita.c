/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "input_owner.h"
#include <psp2/kernel/threadmgr.h>

static uint64_t clock_us(void *ctx)
{
	(void)ctx;
	return sceKernelGetSystemTimeWide();
}

static int acquire(void *ctx)
{
	(void)ctx;
	return vauInputAcquire();
}

static int acquire_process(void *ctx, int32_t process)
{
	(void)ctx;
	return vauInputAcquireForProcess(process);
}

static int heartbeat(void *ctx)
{
	(void)ctx;
	return vauInputHeartbeat();
}

static int submit(void *ctx, const VauSequence *s, const VauEvent *e)
{
	(void)ctx;
	return vauInputSubmit(s, e);
}

static int submit_touch(void *ctx, const VauSequence *s, const VauEvent *e,
                        const VauTouchState *touch)
{
	(void)ctx;
	return vauInputSubmitTouch(s, e, touch);
}

static int cancel(void *ctx)
{
	(void)ctx;
	return vauInputCancel();
}

static int enqueue(void *ctx, const VauSequence *s, const VauEvent *e, const VauTouchState *touch)
{
	(void)ctx;
	return vauInputEnqueue(s, e, touch);
}

static int release(void *ctx)
{
	(void)ctx;
	return vauInputRelease();
}

static int status(void *ctx, VauStatus *out)
{
	(void)ctx;
	return vauInputGetStatus(out);
}
const struct vau_input_bridge vau_vita_input_bridge = { NULL,         clock_us, acquire,
	                                                    heartbeat,    submit,   cancel,
	                                                    release,      status,   acquire_process,
	                                                    submit_touch, enqueue };
