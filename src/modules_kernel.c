/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "vau_modules.h"
#include "vita_agent.h"
#include "file_ops.h"
#include <psp2kern/kernel/modulemgr.h>
#include <string.h>

static int equal_path(const char *a, const char *b)
{
	while (*a && *b) {
		unsigned x = (unsigned char)*a++, y = (unsigned char)*b++;

		if (x >= 'A' && x <= 'Z')
			x += 32;
		if (y >= 'A' && y <= 'Z')
			y += 32;
		if (x != y)
			return 0;
	}

	return !*a && !*b;
}

int vau_modules_kernel_state(int32_t pid, const char path[256], VauPluginState *out)
{
	if (pid <= 0 || !path || !out || !memchr(path, 0, 256))
		return VAU_INVALID;

	char wanted[VAU_PATH_MAX];

	if (vau_path_normalize(path, wanted, sizeof(wanted)))
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	out->size = sizeof(*out);
	out->abi  = VAU_ABI;

	SceUID ids[256];
	SceSize count = 256;
	int rc        = ksceKernelGetModuleList(pid, 0xff, 1, ids, &count);

	if (rc < 0)
		return rc;

	/* A saturated list is incomplete; never report a false negative. */
	if (count >= 256)
		return VAU_UNSUPPORTED;

	for (unsigned i = 0; i < count; i++) {
		SceKernelModuleInfo info = { .size = sizeof(info) };

		rc = ksceKernelGetModuleInfo(pid, ids[i], &info);
		if (rc < 0)
			return rc;
		if (!memchr(info.path, 0, sizeof(info.path)))
			return VAU_DEVICE_ERROR;

		char observed[VAU_PATH_MAX];

		if (vau_path_normalize(info.path, observed, sizeof(observed)))
			continue;
		if (!equal_path(wanted, observed))
			continue;
		if (!memchr(info.module_name, 0, sizeof(info.module_name)))
			return VAU_DEVICE_ERROR;

		out->loaded       = 1;
		out->module_id    = ids[i];
		out->native_state = info.state;
		memcpy(out->module_name, info.module_name, sizeof(out->module_name));
		return VAU_OK;
	}

	return VAU_OK;
}
