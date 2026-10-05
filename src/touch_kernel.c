/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "touch_kernel.h"
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <taihen.h>
#include <psp2/touch.h>
#include <string.h>

#define TOUCH_MODULE_NID UINT32_C(0xcac035de)
#define TOUCH_TEXT_SIZE  UINT32_C(0x6b44)
#define DECODE_OFFSET    UINT32_C(0x4510)
#define OWNER_OFFSET     UINT32_C(0x994)
static SceUID hook = -1;
static tai_hook_ref_t reference;
static SceKernelSpinlock pose_guard;
static struct vau_touch_pose published;
static int present;

struct native_owner {
	int32_t process;
	int16_t region;
	uint16_t attributes;
};

typedef void (*native_owner_fn)(unsigned port, const int16_t *x, const int16_t *y,
                                struct native_owner *out);
static native_owner_fn coordinate_owner;
extern int vauCtrlGetRoutingProcess(int32_t *process);
extern int ksceTouchGetPanelInfo(unsigned port, SceTouchPanelInfo *out);

int vau_touch_kernel_panel(unsigned port, struct vau_touch_panel *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (port >= 2)
		return VAU_INVALID;

	_Static_assert(sizeof(SceTouchPanelInfo) == 0x30, "Native panel geometry ABI");

	SceTouchPanelInfo native = { 0 };
	int rc                   = ksceTouchGetPanelInfo(port, &native);

	if (rc < 0)
		return rc;
	if (native.minAaX >= native.maxAaX || native.minAaY >= native.maxAaY ||
	    native.minDispX >= native.maxDispX || native.minDispY >= native.maxDispY ||
	    native.minForce > native.maxForce) {
		return VAU_DEVICE_ERROR;
	}

	*out = (struct vau_touch_panel){ native.minAaX,   native.minAaY,   native.maxAaX,
		                             native.maxAaY,   native.minDispX, native.minDispY,
		                             native.maxDispX, native.maxDispY, native.minForce,
		                             native.maxForce };
	return VAU_OK;
}

static int32_t owner(void *context, unsigned port, int16_t x, int16_t y)
{
	(void)context;

	struct native_owner result = { -1, -1, 0 };

	/* PID/region in the output record establish whether a match was found. */
	coordinate_owner(port, &x, &y, &result);
	return result.process > 0 && result.region >= 0 && result.region < 8 ? result.process
	                                                                     : VAU_STALE;
}

static int decode(unsigned panels, const void *packet, unsigned bytes,
                  struct vau_touch_frame *front, struct vau_touch_frame *back)
{
	int rc = TAI_CONTINUE(int, reference, panels, packet, bytes, front, back);

	if (rc != 0 || !(panels & 3u))
		return rc;

	struct vau_touch_pose pose;
	SceKernelIntrStatus state = ksceKernelSpinlockLowLockCpuSuspendIntr(&pose_guard);
	int available             = present;

	if (available)
		pose = published;
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&pose_guard, state);
	if (!available)
		return rc;

	uint64_t now = (uint64_t)ksceKernelGetSystemTimeWide();

	if (now < pose.refreshed_us || now >= pose.until_us)
		return rc;

	int32_t process = -1;

	if (pose.process && vauCtrlGetRoutingProcess(&process) < 0)
		return rc;

	/* Decoder mask zero is a native release path; never replace it with
	 * contacts. A single-panel sample must not synthesize the other panel. */
	(void)vau_touch_override(&pose, now, process, panels & 1u ? front : NULL,
	                         panels & 2u ? back : NULL, owner, NULL);
	return rc;
}

int vau_touch_kernel_enable(void)
{
	if (hook >= 0)
		return VAU_OK;

	tai_module_info_t module = { .size = sizeof(module) };
	int rc                   = taiGetModuleInfoForKernel(KERNEL_PID, "SceTouch", &module);

	if (rc < 0)
		return rc;
	if (module.module_nid != TOUCH_MODULE_NID)
		return VAU_UNSUPPORTED;

	SceKernelModuleInfo info = { .size = sizeof(info) };

	rc = ksceKernelGetModuleInfo(KERNEL_PID, module.modid, &info);
	if (rc < 0)
		return rc;

	const unsigned char *text = info.segments[0].vaddr;

	if (!text || info.segments[0].memsz != TOUCH_TEXT_SIZE || !(info.segments[0].perms & 1u))
		return VAU_UNSUPPORTED;

	/* Decoder prologue has no address relocations. Reject a modified entry
	 * rather than blindly patching a different layout or prior offset hook. */
	static const unsigned char decoder_entry[16] = {
		0x2d, 0xe9, 0xf0, 0x4f, 0x85, 0xb0, 0x0e, 0x9c,
		0x9b, 0x46, 0x82, 0x46, 0xcd, 0xe9, 0x01, 0x12,
	};
	static const unsigned char owner_entry[32] = {
		0x2d, 0xe9, 0xf0, 0x4f, 0x47, 0xf2, 0x30, 0x2a, 0x87, 0xb0, 0xc8,
		0xf2, 0x00, 0x1a, 0xf4, 0x24, 0x40, 0xf2, 0x00, 0x05, 0xc0, 0xf2,
		0x00, 0x05, 0x03, 0x93, 0x04, 0xfb, 0x00, 0xa4, 0xd5, 0xf8,
	};

	/* Only MOVW/MOVT address immediate bits may differ after relocation.
	 * Preserve instruction opcodes and destination registers in those slots. */
	static const unsigned char owner_mask[32] = {
		255, 255, 255, 255, 240, 251, 0, 143, 255, 255, 240, 251, 0,   143, 255, 255,
		240, 251, 0,   143, 240, 251, 0, 143, 255, 255, 255, 255, 255, 255, 255, 255,
	};

	if (memcmp(text + DECODE_OFFSET, decoder_entry, sizeof(decoder_entry)))
		return VAU_UNSUPPORTED;

	for (unsigned i = 0; i < sizeof(owner_entry); i++)
		if ((text[OWNER_OFFSET + i] & owner_mask[i]) != (owner_entry[i] & owner_mask[i]))
			return VAU_UNSUPPORTED;
	coordinate_owner = (native_owner_fn)(uintptr_t)(text + OWNER_OFFSET + 1u);

	/* The function pointer is ready before the installed hook can execute.
	 * Published input remains absent until the caller validates a pose. */
	SceUID installed = taiHookFunctionOffsetForKernel(KERNEL_PID, &reference, module.modid, 0,
	                                                  DECODE_OFFSET, 1, decode);

	if (installed < 0) {
		coordinate_owner = NULL;
		return installed;
	}

	hook = installed;
	return VAU_OK;
}

int vau_touch_kernel_publish(const struct vau_touch_pose *pose,
                             const struct vau_touch_panel panels[2])
{
	int rc = vau_touch_pose_validate(pose, panels);

	if (rc < 0)
		return rc;
	if (hook < 0)
		return VAU_UNSUPPORTED;

	/* Geometry validation and native lookups run outside this short-held lock.
	 * No path takes the native Touch lock while holding pose_guard. */
	SceKernelIntrStatus state = ksceKernelSpinlockLowLockCpuSuspendIntr(&pose_guard);

	published = *pose;
	present   = 1;
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&pose_guard, state);
	return VAU_OK;
}

void vau_touch_kernel_clear(void)
{
	SceKernelIntrStatus state = ksceKernelSpinlockLowLockCpuSuspendIntr(&pose_guard);

	present = 0;
	memset(&published, 0, sizeof(published));
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&pose_guard, state);
}
