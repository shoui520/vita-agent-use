/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "shell_jpeg.h"
#include "vita_agent.h"
#include <psp2/kernel/modulemgr.h>
#include <taihen.h>
#include <string.h>
#include <limits.h>

extern void *vauPafMalloc(size_t size);
extern void vauPafFree(void *pointer);
static int (*buffer_sizes)(const uint32_t *, uint32_t *);
static int (*encode_image)(const uintptr_t *, const uintptr_t *);
static void *(*capture_context)(void);

static int bind_shell(void)
{
	if (buffer_sizes && encode_image && capture_context)
		return VAU_OK;

	tai_module_info_t tai = { .size = sizeof(tai) };
	int rc                = taiGetModuleInfo("SceShell", &tai);

	if (rc < 0)
		return rc;
	if (tai.module_nid != 0x5549bf1fu)
		return VAU_UNSUPPORTED;

	SceKernelModuleInfo info = { .size = sizeof(info) };

	rc = sceKernelGetModuleInfo(tai.modid, &info);
	if (rc < 0)
		return rc;

	uintptr_t base = (uintptr_t)info.segments[0].vaddr;

	if (!base || info.segments[0].memsz < 0x366678u)
		return VAU_UNSUPPORTED;

	buffer_sizes    = (void *)(base + 0x366060u + 1);
	encode_image    = (void *)(base + 0x36638au + 1);
	capture_context = (void *)(base + 0x244c64u + 1);
	return VAU_OK;
}

int vau_shell_capture_buffer(void **pixels, size_t *capacity)
{
	if (!pixels || !capacity)
		return VAU_INVALID;

	*pixels   = NULL;
	*capacity = 0;

	int rc = bind_shell();

	if (rc < 0)
		return rc;

	unsigned char *context = capture_context();

	if (!context)
		return VAU_UNSUPPORTED;

	/* Borrow the buffer Shell allocates through its graphics allocator for
	 * PS+START. Never free it, or reuse it during an active native screenshot. */
	if (*(uint32_t *)(context + 0xe7c))
		return VAU_BUSY;

	void *base    = *(void **)(context + 0xe70);
	unsigned size = *(uint32_t *)(context + 0xe74);

	if (!base || size < 960u * 544u * 4u)
		return VAU_DEVICE_ERROR;

	*pixels   = base;
	*capacity = size;
	return VAU_OK;
}

int vau_shell_jpeg(const void *pixels, unsigned width, unsigned height, unsigned pitch,
                   void *output, size_t capacity, unsigned ratio, size_t *bytes)
{
	if (!bytes)
		return VAU_INVALID;

	*bytes = 0;
	if (!pixels || !output || !width || width > 960 || !height || height > 544 || pitch < width ||
	    pitch > 960 || !capacity || capacity > INT_MAX || !ratio || ratio > 255) {
		return VAU_INVALID;
	}

	int rc = bind_shell();

	if (rc < 0)
		return rc;

	/* Display format 0 is little-endian A8B8G8R8: R,G,B,A bytes.
	 * Shell reader format 4 uses R=0,G=1,B=2,A=3; format 6 swaps R/B. */
	uint32_t image[10] = {
		(uint32_t)(uintptr_t)pixels, width, height, pitch * 4, 0, 0, 0, 0, 4, 0,
	};
	uint32_t settings[7] = {
		(uint32_t)(uintptr_t)image, 0, 0, 0, 255u | (ratio << 8), 0x3f800000, 0x3f800000,
	};
	uint32_t sizes[2] = { 0 };

	rc = buffer_sizes(settings, sizes);
	if (rc < 0)
		return rc;
	if (!sizes[0] || sizes[0] > capacity || sizes[1] < 16 || sizes[1] > 1024u * 1024u)
		return VAU_DEVICE_ERROR;

	void *work = vauPafMalloc(sizes[1]);

	if (!work)
		return VAU_DEVICE_ERROR;

	uintptr_t args[4]    = { (uintptr_t)settings, 0, 0, 0 };
	uintptr_t buffers[8] = { (uintptr_t)output, capacity, (uintptr_t)work, sizes[1], 0, 0, 0, 0 };

	rc = encode_image(args, buffers);
	vauPafFree(work);
	if (rc < 0)
		return rc;

	unsigned char *jpeg = output;

	if (rc < 4 || (size_t)rc > capacity || jpeg[0] != 0xff || jpeg[1] != 0xd8 ||
	    jpeg[rc - 2] != 0xff || jpeg[rc - 1] != 0xd9) {
		return VAU_DEVICE_ERROR;
	}

	*bytes = (size_t)rc;
	return VAU_OK;
}
