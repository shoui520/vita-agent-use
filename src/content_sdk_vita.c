/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_delete.h"
#include "content_sdk.h"
#include "format.h"
#include "native_ops.h"
#include <psp2/io/dirent.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/sysmodule.h>
#include <stddef.h>
#include <string.h>
#include <taihen.h>

static int loaded(void *context)
{
	(void)context;

	int rc = sceSysmoduleIsLoadedInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);

	return (uint32_t)rc == 0x805a1001u ? 1 : rc;
}

static int load(void *context)
{
	(void)context;
	return sceSysmoduleLoadModuleInternal(SCE_SYSMODULE_INTERNAL_PROMOTER_UTIL);
}

static int resolve(void *context, uint32_t nid, uintptr_t *address)
{
	(void)context;
	return taiGetModuleExportFunc("ScePromoterUtil", 0x31f237b6, nid, address);
}

void vau_vita_content_sdk_init(struct vau_content_sdk *s)
{
	const struct vau_content_sdk_loader loader = { NULL, loaded, load, resolve };

	vau_content_sdk_init(s, &loader);

	/* Keep the module resident. Init/Exit register a ShellSvc client identity,
	 * not a plugin-specific refcount. Exit could unregister an existing Shell
	 * user and destroy its shared worker. Never tear that down from a plugin. */
}

static int run(SceSize size, void *args)
{
	if (size != sizeof(struct vau_content_worker *) || !args)
		return VAU_INVALID;

	struct vau_content_worker *w;

	memcpy(&w, args, sizeof(w));

	int rc = w->execute(w->context, w->title);

	w->result = rc;
	atomic_store_explicit(&w->done, 1, memory_order_release);
	return rc;
}

void vau_content_worker_init(struct vau_content_worker *w)
{
	memset(w, 0, sizeof(*w));
	w->thread = -1;
	atomic_init(&w->done, 0);
}

static int reclaim(struct vau_content_worker *w)
{
	if (w->thread < 0)
		return VAU_OK;
	if (w->started) {
		unsigned timeout = 1;
		int rc           = sceKernelWaitThreadEnd(w->thread, NULL, &timeout);

		if (rc < 0)
			return VAU_BUSY;

		w->started = 0;
	}

	int rc = sceKernelDeleteThread(w->thread);

	if (rc < 0)
		return rc;

	w->thread = -1;
	return VAU_OK;
}

int vau_content_worker_start(struct vau_content_worker *w, const char *title,
                             int (*execute)(void *, const char *), void *context)
{
	if (!w || !execute || !vau_title_valid(title) || !strncmp(title, "NPXS", 4))
		return VAU_INVALID;

	/* An uncollected result, failed cleanup or still-running native call owns
	 * this slot. No second operation may overwrite its title/callback. */
	if (w->thread >= 0 || atomic_load_explicit(&w->done, memory_order_acquire))
		return VAU_BUSY;

	memcpy(w->title, title, sizeof(w->title));
	w->execute = execute;
	w->context = context;

	int rc = sceKernelCreateThread("VauContent", run, 0x10000100, VAU_CONTENT_WORKER_STACK, 0, 0,
	                               NULL);

	if (rc < 0)
		return rc;

	w->thread = rc;

	struct vau_content_worker *argument = w;

	rc = sceKernelStartThread(w->thread, sizeof(argument), &argument);
	if (rc < 0) {
		w->result = rc;
		atomic_store_explicit(&w->done, 1, memory_order_release);
		(void)reclaim(w);
		return rc;
	}

	w->started = 1;
	return VAU_OK;
}

int vau_content_worker_poll(struct vau_content_worker *w, int *result)
{
	if (!w || !result)
		return VAU_INVALID;
	if (!atomic_load_explicit(&w->done, memory_order_acquire))
		return w->thread >= 0 ? VAU_BUSY : VAU_STALE;

	/* Publication of the SDK result precedes the OS's thread-exit event. Wait
	 * for both before releasing storage or reporting a collectible result. */
	int rc = reclaim(w);

	if (rc)
		return rc;

	*result = w->result;
	atomic_store_explicit(&w->done, 0, memory_order_release);
	w->execute = NULL;
	w->context = NULL;
	return VAU_OK;
}

static int same(const struct vau_file_info *a, const struct vau_file_info *b)
{
	return a->bytes == b->bytes && a->mode == b->mode && a->attributes == b->attributes &&
	       a->kind == b->kind && a->year == b->year && a->month == b->month && a->day == b->day &&
	       a->hour == b->hour && a->minute == b->minute && a->second == b->second &&
	       a->microsecond == b->microsecond;
}

static int matches_stat(const struct vau_file_info *i, const SceIoStat *s)
{
	return s->st_size >= 0 && i->kind == VAU_FILE_REGULAR && i->bytes == (uint64_t)s->st_size &&
	       i->mode == (uint32_t)s->st_mode && i->attributes == s->st_attr &&
	       i->year == s->st_mtime.year && i->month == s->st_mtime.month &&
	       i->day == s->st_mtime.day && i->hour == s->st_mtime.hour &&
	       i->minute == s->st_mtime.minute && i->second == s->st_mtime.second &&
	       i->microsecond == s->st_mtime.microsecond;
}

int vau_vita_savedata_backup(unsigned user, const char *save, int (*stopped)(void *), void *ctx,
                             struct vau_savedata_backup *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (user >= 64 || !stopped || !vau_content_savedata_id_valid(save))
		return VAU_INVALID;
	if (stopped(ctx))
		return VAU_DENIED;

	/* Native firmware rejects nonconventional IDs before directory access;
	 * its caller ignores that backup-helper error and cleans the live save. */
	if (!vau_content_savedata_backup_eligible(save))
		return VAU_OK;

	char root[64], path[VAU_PATH_MAX], normalized[VAU_PATH_MAX];

	vau_snprintf(root, sizeof(root), "ux0:user/%02u/savedata_backup", user);

	struct vau_savedata_backup result = { 0 };
	int rc = vau_file_stat(vau_vita_file_stat, NULL, root, &result.directory);

	if (rc == (int)UINT32_C(0x80010002))
		return stopped(ctx) ? VAU_DENIED : VAU_OK;
	if (rc)
		return rc;
	if (result.directory.kind != VAU_FILE_DIRECTORY)
		return VAU_DENIED;

	result.directory_present = 1;

	int fd = sceIoDopen(root);

	if (fd < 0)
		return fd;

	SceIoDirent entry;

	for (;;) {
		if (stopped(ctx)) {
			rc = VAU_DENIED;
			break;
		}

		memset(&entry, 0, sizeof(entry));
		rc = sceIoDread(fd, &entry);
		if (rc <= 0)
			break;

		++result.entries_read;

		const char *end = memchr(entry.d_name, 0, sizeof(entry.d_name));

		if (!end) {
			rc = VAU_DEVICE_ERROR;
			break;
		}

		int match =
		        vau_content_savedata_backup_match(save, entry.d_name, (size_t)(end - entry.d_name),
		                                          SCE_S_ISREG(entry.d_stat.st_mode));

		if (match < 0) {
			rc = match;
			break;
		}

		if (!match)
			continue;

		int n = vau_snprintf(path, sizeof(path), "%s/%s", root, entry.d_name);

		if (n < 0 || (size_t)n >= sizeof(path) || strchr(entry.d_name, '/') ||
		    vau_path_normalize(path, normalized, sizeof(normalized)) || strcmp(path, normalized)) {
			rc = VAU_INVALID;
			break;
		}

		rc = vau_file_stat(vau_vita_file_stat, NULL, path, &result.file);
		if (!rc && !matches_stat(&result.file, &entry.d_stat))
			rc = VAU_STALE;
		if (!rc) {
			memcpy(result.filename, entry.d_name, 32);
			result.found = 1;
		}
		break;
	}

	int closed = sceIoDclose(fd);

	if (!rc && closed < 0)
		rc = closed;
	if (!rc && stopped(ctx))
		rc = VAU_DENIED;
	if (!rc) {
		struct vau_file_info after;

		rc = vau_file_stat(vau_vita_file_stat, NULL, root, &after);
		if (!rc && !same(&result.directory, &after))
			rc = VAU_STALE;
	}

	if (!rc && stopped(ctx))
		rc = VAU_DENIED;
	if (!rc)
		*out = result;
	return rc;
}
