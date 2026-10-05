/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_media.h"
#include "native_ops.h"
#include <psp2/appmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/sysmodule.h>
#include <stddef.h>
#include <string.h>
#include <taihen.h>

static int media_db_vita_loaded(void *ctx)
{
	(void)ctx;

	int rc = sceSysmoduleIsLoadedInternal(SCE_SYSMODULE_INTERNAL_DBUTIL);

	/* SCE_SYSMODULE_ERROR_UNLOADED is the loader contract's "needs load", not a failure. */
	return (uint32_t)rc == UINT32_C(0x805a1001) ? 1 : rc;
}

static int media_db_vita_load(void *ctx)
{
	(void)ctx;
	return sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_DBUTIL);
}

static int media_db_vita_resolve(void *ctx, uint32_t nid, uintptr_t *address)
{
	(void)ctx;
	return taiGetModuleExportFunc("SceDbutil", UINT32_C(0x36f82e95), nid, address);
}

void vau_vita_media_db_init(struct vau_media_db *s)
{
	const struct vau_content_sdk_loader loader = { NULL, media_db_vita_loaded, media_db_vita_load,
		                                           media_db_vita_resolve };
	vau_media_db_init(s, &loader);

	/* Retain this shared native module for process lifetime. This initializer
	 * neither opens a database nor loads a module at Shell startup. */
}

static int media_modules_vita_resolve(void *context, uint32_t nid, uintptr_t *address)
{
	(void)context;
	return taiGetModuleExportFunc("ScePaf", UINT32_C(0x3d643ce8), nid, address);
}

void vau_vita_media_modules_init(struct vau_media_modules *s, void *context, int (*stopped)(void *))
{
	vau_media_modules_init(s, context, media_modules_vita_resolve, stopped);

	/* PAF already belongs to Shell. Do not load/unload or initialize PAF here. */
}

static int media_music_vita_mount(void *context, int type, char *point)
{
	(void)context;
	return sceAppMgrAppDataMount(type, point);
}

static int media_music_vita_unmount(void *context, const char *point)
{
	(void)context;
	return sceAppMgrUmount(point);
}

void vau_vita_media_music_init(struct vau_media_music *s)
{
	vau_media_music_init(s, NULL, media_music_vita_mount, media_music_vita_unmount);
}

static int media_loopback_vita_drm_context(void *context, char *out)
{
	(void)context;

	uintptr_t address = 0;
	int rc = taiGetModuleExportFunc("SceVideoProfiler", 0x68485219, 0xb327ffa8, &address);

	if (rc)
		return rc;
	return address ? ((int (*)(char *))address)(out) : VAU_DEVICE_ERROR;
}

static int media_loopback_vita_mount(void *context, int type, const char *drm, char *point)
{
	(void)context;

	uintptr_t address = 0;
	int rc            = taiGetModuleExportFunc("SceDriverUser", 0xa6605d6f, 0x33cd76dd, &address);

	if (rc)
		return rc;
	return address ? ((int (*)(int, const char *, char *))address)(type, drm, point)
	               : VAU_DEVICE_ERROR;
}

static int media_loopback_vita_unmount(void *context, const char *point)
{
	(void)context;
	return sceAppMgrUmount(point);
}

void vau_vita_media_loopback_init(struct vau_media_loopback *s)
{
	vau_media_loopback_init(s, NULL, media_loopback_vita_drm_context, media_loopback_vita_mount,
	                        media_loopback_vita_unmount);
}

static int media_path_vita_raw(void *context, char *input, char *output, int capacity)
{
	(void)context;

	/* Actual 3.65 syscall reads argument 1 and writes argument 2; argument 3 is
	 * output capacity. SDK parameter comments currently describe the reverse. */
	return sceAppMgrGetRawPath(input, output, capacity);
}

int vau_vita_content_media_path(const char *path, struct vau_content_media_path *out)
{
	return vau_content_media_path_resolve(NULL, media_path_vita_raw, path, out);
}

static int media_session_vita_stopped(void *context)
{
	struct vau_media_session_vita *s = context;

	return s->stopped && s->stopped(s->stop_context);
}

static int media_session_vita_resident(void *context)
{
	(void)context;
	return 0;
}

static int media_session_vita_unexpected_load(void *context)
{
	(void)context;
	return VAU_DEVICE_ERROR;
}

static int media_session_vita_modules(void *context, uint32_t nid, uintptr_t *address)
{
	(void)context;
	return taiGetModuleExportFunc("ScePaf", 0x3d643ce8, nid, address);
}

static int media_session_vita_operation(void *context, uint32_t nid, uintptr_t *address)
{
	(void)context;
	return taiGetModuleExportFunc("SceContentOperation", 0x0d64b6ed, nid, address);
}

static int media_session_vita_profiler(void *context, uint32_t nid, uintptr_t *address)
{
	(void)context;
	return taiGetModuleExportFunc("SceVideoProfiler", 0x68485219, nid, address);
}

static int media_session_vita_prepare(void *context)
{
	struct vau_media_session_vita *s      = context;
	uintptr_t media_session_vita_allocate = 0, media_session_vita_release = 0;
	int rc = taiGetModuleExportFunc("ScePaf", 0xa7d28dae, 0xfc5cd359, &media_session_vita_allocate);

	if (!rc)
		rc = taiGetModuleExportFunc("ScePaf", 0xa7d28dae, 0x1b77082e, &media_session_vita_release);
	if (!rc && (!media_session_vita_allocate || !media_session_vita_release))
		rc = VAU_DEVICE_ERROR;
	if (!rc) {
		s->allocate = (void *(*)(size_t))media_session_vita_allocate;
		s->release  = (void (*)(void *))media_session_vita_release;
	}

	return rc;
}

static void *media_session_vita_allocate(void *context, size_t bytes)
{
	return ((struct vau_media_session_vita *)context)->allocate(bytes);
}

static void media_session_vita_release(void *context, void *value)
{
	((struct vau_media_session_vita *)context)->release(value);
}

static int media_session_vita_mount_begin(void *context, unsigned category)
{
	struct vau_media_session_vita *s = context;

	return category == 2 ? vau_media_music_open(&s->music) : 0;
}

static int media_session_vita_mount_end(void *context)
{
	return vau_media_music_close(&((struct vau_media_session_vita *)context)->music);
}

static int media_session_vita_path_begin(void *context, const char *path, const char **resolved)
{
	struct vau_media_session_vita *s = context;

	if (strncmp(path, "empr0:", 6)) {
		*resolved = path;
		return 0;
	}

	int rc = vau_media_loopback_open(&s->loopback, path);

	if (!rc)
		*resolved = vau_media_loopback_path(&s->loopback);
	return rc;
}

static int media_session_vita_path_end(void *context)
{
	return vau_media_loopback_close(&((struct vau_media_session_vita *)context)->loopback);
}

static int media_session_vita_resolve_path(void *context, const char *path,
                                           struct vau_content_media_path *out)
{
	(void)context;
	return vau_vita_content_media_path(path, out);
}

void vau_vita_media_session_init(struct vau_media_session_vita *s, void *context,
                                 int (*stop)(void *))
{
	s->stop_context = context;
	s->stopped      = stop;
	vau_vita_media_music_init(&s->music);
	vau_vita_media_loopback_init(&s->loopback);
	s->allocate = NULL;
	s->release  = NULL;

	const struct vau_media_session_backend backend = {
		.operation      = { s, media_session_vita_resident, media_session_vita_unexpected_load,
		                    media_session_vita_operation },
		.profiler       = { s, media_session_vita_resident, media_session_vita_unexpected_load,
		                    media_session_vita_profiler },
		.context        = s,
		.module_resolve = media_session_vita_modules,
		.prepare_memory = media_session_vita_prepare,
		.mount_begin    = media_session_vita_mount_begin,
		.mount_end      = media_session_vita_mount_end,
		.path_begin     = media_session_vita_path_begin,
		.path_end       = media_session_vita_path_end,
		.resolve_path   = media_session_vita_resolve_path,
		.allocate       = media_session_vita_allocate,
		.release        = media_session_vita_release,
		.stopped        = media_session_vita_stopped
	};

	vau_media_session_init(&s->session, &backend);
	vau_vita_media_db_init(&s->session.database);

	/* No native call, module acquisition or database open at initialization. */
}

struct readable_block {
	uintptr_t start, end;
};

static int media_temp_vita_read_memory(void *context, uintptr_t address, void *out, size_t bytes)
{
	struct readable_block *cache = context;

	if (!address || !bytes || bytes > UINT32_MAX || address > UINT32_MAX - bytes)
		return VAU_DEVICE_ERROR;

	uintptr_t end = address + bytes;

	if (address < cache->start || end > cache->end) {
		SceKernelMemBlockInfo block = { .size = sizeof(block) };
		int rc                      = sceKernelGetMemBlockInfoByAddr((void *)address, &block);

		if (rc < 0)
			return rc;

		uintptr_t base = (uintptr_t)block.mappedBase;

		if (!(block.access & SCE_KERNEL_MEMORY_ACCESS_R) || !block.mappedSize ||
		    base > UINT32_MAX - block.mappedSize || address < base ||
		    end > base + block.mappedSize) {
			return VAU_DEVICE_ERROR;
		}

		cache->start = base;
		cache->end   = base + block.mappedSize;
	}

	memcpy(out, (const void *)address, bytes);
	return 0;
}

int vau_vita_media_temp_directory(struct vau_media_session *session,
                                  struct vau_media_temp_directory *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!session || !session->ready || !session->database.ready)
		return VAU_INVALID;
	if (session->busy)
		return VAU_BUSY;

	tai_module_info_t info = { .size = sizeof(info) };
	int rc                 = taiGetModuleInfo("SceSqliteVsh", &info);

	if (rc)
		return rc;

	struct readable_block cache = { 0 };

	return vau_media_temp_directory_read(&cache, media_temp_vita_read_memory, info.exports_start,
	                                     info.exports_end, out);
}
