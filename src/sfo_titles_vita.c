/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "file_ops.h"
#include "format.h"
#include "sfo_titles.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <string.h>

struct source {
	int fd;
	uint64_t bytes;
};

static int exact(void *ctx, uint64_t offset, void *data, uint32_t count)
{
	struct source *s = ctx;
	if (offset > s->bytes || count > s->bytes - offset || offset > INT64_MAX)
		return VAU_INVALID;

	SceOff at = sceIoLseek(s->fd, (SceOff)offset, SCE_SEEK_SET);

	if (at < 0)
		return (int)at;
	if ((uint64_t)at != offset)
		return VAU_DEVICE_ERROR;

	uint32_t done = 0;

	while (done < count) {
		int n = sceIoRead(s->fd, (unsigned char *)data + done, count - done);

		if (n < 0)
			return n;
		if (!n)
			return VAU_STALE;
		if ((uint32_t)n > count - done)
			return VAU_DEVICE_ERROR;

		done += (uint32_t)n;
	}

	return VAU_OK;
}

static int unchanged(const SceIoStat *a, const SceIoStat *b)
{
	return a->st_mode == b->st_mode && a->st_size == b->st_size && a->st_attr == b->st_attr &&
	       a->st_mtime.year == b->st_mtime.year && a->st_mtime.month == b->st_mtime.month &&
	       a->st_mtime.day == b->st_mtime.day && a->st_mtime.hour == b->st_mtime.hour &&
	       a->st_mtime.minute == b->st_mtime.minute && a->st_mtime.second == b->st_mtime.second &&
	       a->st_mtime.microsecond == b->st_mtime.microsecond;
}

static int read_titles_file(const char *path, int pbp, struct vau_sfo_titles *out)
{
	if (!path || !out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	struct vau_file_info info;
	int rc = vau_file_stat(vau_vita_file_stat, NULL, path, &info);

	if (rc)
		return rc;
	if (info.kind != VAU_FILE_REGULAR)
		return VAU_INVALID;
	if (!pbp && info.bytes > VAU_SFO_METADATA_BYTES)
		return VAU_UNSUPPORTED;

	int fd = sceIoOpen(path, SCE_O_RDONLY, 0);

	if (fd < 0)
		return fd;

	SceIoStat before = { 0 }, after = { 0 };

	rc = sceIoGetstatByFd(fd, &before);
	if (!rc && (!SCE_S_ISREG(before.st_mode) || before.st_size < 0 ||
	            (uint64_t)before.st_size != info.bytes)) {
		rc = VAU_STALE;
	}

	if (!rc) {
		struct source s = { fd, (uint64_t)before.st_size };

		rc = pbp ? vau_pbp_titles_read(exact, &s, s.bytes, out)
		         : vau_sfo_titles_read(exact, &s, s.bytes, out);
	}

	if (!rc) {
		rc = sceIoGetstatByFd(fd, &after);
		if (!rc && !unchanged(&before, &after))
			rc = VAU_STALE;
	}

	int closed = sceIoClose(fd);

	if (!rc && closed < 0)
		rc = closed;
	if (rc)
		memset(out, 0, sizeof(*out));
	return rc;
}

int vau_vita_savedata_titles(const char *directory, struct vau_sfo_titles *out)
{
	if (!directory || !out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	char path[VAU_PATH_MAX];
	int n = vau_snprintf(path, sizeof(path), "%s/PARAM.SFO", directory);

	if (n < 0 || (size_t)n >= sizeof(path))
		return VAU_INVALID;
	return read_titles_file(path, 0, out);
}

int vau_vita_application_titles(const char *directory, struct vau_sfo_titles *out, char source[16])
{
	if (!directory || !out || !source)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	memset(source, 0, 16);
	static const char *const files[] = { "EBOOT.PBP", "PBOOT.PBP", "PARAM.PBP" };
	for (unsigned i = 0; i < 3; i++) {
		char path[VAU_PATH_MAX];
		int n = vau_snprintf(path, sizeof(path), "%s/%s", directory, files[i]);

		if (n < 0 || (size_t)n >= sizeof(path))
			return VAU_INVALID;

		struct vau_file_info info;
		int rc = vau_file_stat(vau_vita_file_stat, NULL, path, &info);

		if ((uint32_t)rc == UINT32_C(0x80010002))
			continue;
		if (rc)
			return rc;

		memcpy(source, files[i], strlen(files[i]) + 1);
		return read_titles_file(path, 1, out);
	}

	return (int)UINT32_C(0x80010002);
}
