/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "capture_kernel.h"
#include <psp2kern/display.h>
#include <psp2kern/kernel/threadmgr.h>
#include <stdatomic.h>
#include <string.h>

static atomic_flag busy = ATOMIC_FLAG_INIT;

/* Same Display DMAC entry called by AppMgr's native PS+START path. */
extern int ksceDisplayCaptureFrameBufDMACInternal(SceUID pid, int head, int index,
                                                  SceDisplayFrameBuf *buffer);
_Static_assert(sizeof(VauFrameInfo) == 56, "Frame metadata ABI");

static int same_display(const SceDisplayFrameBufInfo *a, const SceDisplayFrameBufInfo *b)
{
	return a->pid == b->pid && a->resolution == b->resolution &&
	       a->framebuf.width == b->framebuf.width && a->framebuf.height == b->framebuf.height &&
	       a->framebuf.pitch == b->framebuf.pitch &&
	       a->framebuf.pixelformat == b->framebuf.pixelformat;
}

int vau_capture_kernel(void *pixels, uint32_t capacity, VauFrameInfo *info)
{
	if (!pixels || !info)
		return VAU_INVALID;

	memset(info, 0, sizeof(*info));
	if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire))
		return VAU_BUSY;

	int rc;
	uint64_t started = (uint64_t)ksceKernelGetSystemTimeWide();
	int head         = ksceDisplayGetPrimaryHead();

	if (head < 0) {
		rc = head;
		goto done;
	}

	if (head > 1) {
		rc = VAU_UNSUPPORTED;
		goto done;
	}

	SceDisplayFrameBufInfo before = { .size = sizeof(before) }, after = { .size = sizeof(after) };

	/* Shell renders on display index1. Index0 can have no configured PID at
	 * LiveArea; keep index0 as fallback for configurations that use it. */
	int index = 1;

	rc = ksceDisplayGetProcFrameBufInternal(-1, head, index, &before);
	if (rc == (int32_t)0x80029001u) { /* SCE_KERNEL_ERROR_INVALID_PID: no owner on index 1 */
		index       = 0;
		before.size = sizeof(before);
		rc          = ksceDisplayGetProcFrameBufInternal(-1, head, index, &before);
	}

	if (rc < 0)
		goto done;

	SceDisplayFrameBuf *fb = &before.framebuf;

	*info = (VauFrameInfo){ .size         = sizeof(*info),
		                    .abi          = VAU_ABI,
		                    .width        = fb->width,
		                    .height       = fb->height,
		                    .pitch        = fb->pitch,
		                    .pixel_format = fb->pixelformat,
		                    .head         = (uint32_t)head,
		                    .process_id   = before.pid,
		                    .vblank_count = before.vblankcount,
		                    .started_us   = started };
	if (before.pid <= 0 || (fb->size != 0x18 && fb->size != 0x1c) || !fb->base || !fb->width ||
	    fb->width > 960 || !fb->height || fb->height > 544 || fb->pitch < fb->width ||
	    fb->pitch > 2048 || fb->pixelformat != SCE_DISPLAY_PIXELFORMAT_A8B8G8R8) {
		rc = VAU_UNSUPPORTED;
		goto done;
	}

	uint32_t pitch = (fb->width + 63u) & ~63u, bytes = pitch * fb->height * 4;

	if (capacity < bytes || ((uintptr_t)pixels & 255u) || (uintptr_t)pixels > UINTPTR_MAX - bytes) {
		rc = VAU_INVALID;
		goto done;
	}

	SceDisplayFrameBuf destination = {
		sizeof(destination), pixels, pitch, 0, fb->width, fb->height
	};

	rc = ksceDisplayCaptureFrameBufDMACInternal(before.pid, head, index, &destination);
	if (rc < 0)
		goto done;
	if (destination.base != pixels || destination.pitch != pitch || destination.pixelformat != 0 ||
	    destination.width != fb->width || destination.height != fb->height) {
		rc = VAU_DEVICE_ERROR;
		goto done;
	}

	rc = ksceDisplayGetProcFrameBufInternal(-1, head, index, &after);
	if (rc < 0)
		goto done;
	if (ksceDisplayGetPrimaryHead() != head || !same_display(&before, &after)) {
		rc = VAU_STALE;
		goto done;
	}

	*info = (VauFrameInfo){ sizeof(*info), VAU_ABI,
		                    fb->width,     fb->height,
		                    pitch,         fb->pixelformat,
		                    bytes,         (uint32_t)head,
		                    before.pid,    before.vblankcount,
		                    started,       (uint64_t)ksceKernelGetSystemTimeWide() };
done:
	if (rc < 0) {
		info->bytes       = 0;
		info->finished_us = (uint64_t)ksceKernelGetSystemTimeWide();
	}

	atomic_flag_clear_explicit(&busy, memory_order_release);
	return rc;
}
