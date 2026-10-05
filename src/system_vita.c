/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "native_ops.h"
#include <psp2/appmgr.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/vshbridge.h>
#include <string.h>

/* Exact read-only export called by 3.65 AppUtil SystemParamGetInt. */
extern int vauRegSystemParamGetInt(int id, int *value);

/* Direct native syscall, rather than initializing the AppMgr user wrapper. */
extern int __sceAppMgrGetAppState(SceAppMgrAppState *state, unsigned int length,
                                  unsigned int version);

int vau_vita_system_ui_overlaid(void *context)
{
	(void)context;
	_Static_assert(sizeof(SceAppMgrAppState) == 0x80, "App state ABI");

	SceAppMgrAppState state = { 0 };

	/* Version zero is accepted by the audited native 3.65 implementation. */
	int rc = __sceAppMgrGetAppState(&state, sizeof(state), 0);

	if (rc < 0)
		return rc;
	return state.isSystemUiOverlaid == 0 ? 0 : state.isSystemUiOverlaid == 1 ? 1 : VAU_DEVICE_ERROR;
}

int vau_vita_confirmation_button(uint32_t *mask)
{
	if (!mask)
		return VAU_INVALID;

	*mask = 0;

	int value = -1;
	int rc    = vauRegSystemParamGetInt(0x229142, &value);

	if (rc < 0)
		return rc;
	if (value != 0 && value != 1)
		return VAU_DEVICE_ERROR;

	/* 1 = Cross confirms (most regions), 0 = Circle (Japan): SCE_CTRL_CROSS / SCE_CTRL_CIRCLE. */
	*mask = value ? 0x4000u : 0x2000u;
	return VAU_OK;
}

int vau_vita_confirm_mask(void *context)
{
	(void)context;

	uint32_t mask = 0;
	int rc        = vau_vita_confirmation_button(&mask);

	return rc < 0 ? rc : (int)mask;
}

int vau_vita_system_language(void *context)
{
	(void)context;

	int value = -1;
	int rc    = vauRegSystemParamGetInt(0x37502, &value);

	if (rc < 0)
		return rc;
	return value >= 0 && value <= 19 ? value : VAU_DEVICE_ERROR;
}

int vau_vita_model(void *context)
{
	(void)context;
	return sceKernelGetModel();
}

int vau_vita_firmware(void *context, struct vau_firmware *out)
{
	(void)context;
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	_Static_assert(sizeof(SceKernelSystemSwVersion) == 0x28, "Firmware ABI");

	SceKernelSystemSwVersion info = { .size = sizeof(info) };
	int rc                        = sceKernelGetSystemSwVersion(&info);

	if (rc < 0)
		return rc;

	memcpy(out->text, info.versionString, sizeof(out->text));
	out->version_code = info.version;
	if (!vau_firmware_valid(out)) {
		memset(out, 0, sizeof(*out));
		return VAU_DEVICE_ERROR;
	}

	return VAU_OK;
}

int vau_vita_console_id(void *context, struct vau_console_id *out)
{
	(void)context;
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	/* SDK declares a 32-byte buffer; the ConsoleID is its first 16 bytes. */
	char buffer[32] = { 0 };
	int rc          = _vshSblAimgrGetConsoleId(buffer);

	if (rc >= 0)
		memcpy(out->bytes, buffer, sizeof(out->bytes));

	volatile unsigned char *wipe = (volatile unsigned char *)buffer;

	for (size_t i = 0; i < sizeof(buffer); i++)
		wipe[i] = 0;
	return rc < 0 ? rc : VAU_OK;
}

int vau_vita_memory(void *context, struct vau_memory *out)
{
	(void)context;
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	_Static_assert(sizeof(SceKernelFreeMemorySizeInfo) == 0x10, "Memory query ABI");

	SceKernelFreeMemorySizeInfo info = { .size = sizeof(info) };
	int rc                           = sceKernelGetFreeMemorySize(&info);

	if (rc < 0)
		return rc;
	if (info.size_user < 0 || info.size_cdram < 0 || info.size_phycont < 0)
		return VAU_DEVICE_ERROR;

	out->user_free_bytes    = (uint32_t)info.size_user;
	out->cdram_free_bytes   = (uint32_t)info.size_cdram;
	out->phycont_free_bytes = (uint32_t)info.size_phycont;
	return VAU_OK;
}
