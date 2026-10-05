/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "vau_performance.h"
#include <psp2kern/display.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysroot.h>
#include <taihen.h>
#include <stdatomic.h>
#include <string.h>

extern int vauCtrlGetRoutingProcess(int32_t *);
extern uintptr_t vauSysrootCurrentAddressSpace(void);
extern int vauSysrootProcessTitle(int32_t, char *, uint32_t);

struct partition_info {
	uint32_t base, total, free, count;
};

extern int vauGetPhyMemPartInfo(void *, struct partition_info *);
static tai_hook_ref_t display_ref;
static int hook_id = -1, hook_error = VAU_UNSUPPORTED;
static _Atomic uint32_t enabled, head, frames[2];

static int display_hook(int h, int plane, const SceDisplayFrameBuf *fb, int sync)
{
	int rc = TAI_CONTINUE(int, display_ref, h, plane, fb, sync);
	if (rc >= 0 && atomic_load_explicit(&enabled, memory_order_relaxed) &&
	    h == (int)atomic_load_explicit(&head, memory_order_relaxed) && (unsigned)plane < 2 && fb &&
	    fb->base) {
		atomic_fetch_add_explicit(&frames[plane], 1, memory_order_relaxed);
	}

	return rc;
}

/* Called only on demand by Shell; no hook installation at boot. */
static int read_native(uint32_t on, VauPerformanceRaw *out)
{
	memset(out, 0, sizeof(*out));
	out->size = sizeof(*out);
	out->abi  = VAU_ABI;
	if (on > 1)
		return VAU_INVALID;
	if (on && hook_id < 0) {
		hook_id    = taiHookFunctionExportForKernel(0x10005, &display_ref, "SceDisplay", 0x9FED47AC,
		                                            0x16466675, display_hook);
		hook_error = hook_id < 0 ? hook_id : 0;
	}

	atomic_store_explicit(&enabled, on, memory_order_relaxed);
	if (!on)
		return VAU_OK;

	int display_head = ksceDisplayGetPrimaryHead();

	out->foreground_error = vauCtrlGetRoutingProcess(&out->pid);
	if (out->foreground_error >= 0 && out->pid <= 0)
		out->foreground_error = VAU_DEVICE_ERROR;
	if (out->foreground_error >= 0) {
		if (out->pid == ksceKernelSysrootGetShellPid()) {
			strcpy(out->title, "main");
		} else {
			out->foreground_error =
			        vauSysrootProcessTitle(out->pid, out->title, sizeof(out->title));
		}
	}

	out->fps_error = hook_error;
	if (display_head < 0) {
		out->fps_error = display_head;
	} else {
		atomic_store_explicit(&head, (uint32_t)display_head, memory_order_relaxed);

		int matched = 0;

		for (int plane = 0; plane < 2; plane++) {
			SceDisplayFrameBufInfo info = { .size = sizeof(info) };
			int rc = ksceDisplayGetProcFrameBufInternal(-1, display_head, plane, &info);

			if (rc >= 0 && info.pid == out->pid && info.framebuf.base) {
				out->frames = atomic_load_explicit(&frames[plane], memory_order_relaxed);
				out->plane  = (uint32_t)plane;
				matched     = 1;
				break;
			}
		}

		if (!matched && out->fps_error >= 0)
			out->fps_error = VAU_UNSUPPORTED;
	}

	out->memory_error = out->foreground_error;
	if (out->memory_error < 0)
		return VAU_OK;

	SceKernelProcessContext *context = NULL, previous;
	int rc                           = ksceKernelProcessGetContext(out->pid, &context);

	if (rc >= 0 && !context)
		rc = VAU_DEVICE_ERROR;
	if (rc >= 0)
		rc = ksceKernelProcessSwitchContext(context, &previous);
	if (rc < 0) {
		out->memory_error = rc;
		return VAU_OK;
	}

	uintptr_t cas                   = vauSysrootCurrentAddressSpace();
	static const unsigned offsets[] = { 328, 332, 316, 324 };

	if (!cas || (cas & 3))
		rc = VAU_UNSUPPORTED;
	for (unsigned i = 0; i < 4 && rc >= 0; i++) {
		uintptr_t part = *(const uint32_t *)(cas + offsets[i]);

		if (!part)
			continue; /* No partition allocated for this process. */
		if (part <= 0x1000 || part >= 0x1000000 || (part & 3)) {
			rc = VAU_UNSUPPORTED;
			break;
		}

		struct partition_info info = { 0 };

		rc = vauGetPhyMemPartInfo((void *)part, &info);
		if (rc >= 0 && info.free > info.total)
			rc = VAU_DEVICE_ERROR;
		if (rc >= 0) {
			out->total[i] = info.total;
			out->free[i]  = info.free;
		}
	}

	int restored = ksceKernelProcessSwitchContext(&previous, NULL);

	out->memory_error = restored < 0 ? restored : rc;
	return VAU_OK;
}

int vau_performance_kernel(uint32_t on, VauPerformanceRaw *out)
{
	static atomic_flag busy = ATOMIC_FLAG_INIT;

	if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire))
		return VAU_BUSY;

	int rc = read_native(on, out);

	atomic_flag_clear_explicit(&busy, memory_order_release);
	return rc;
}
