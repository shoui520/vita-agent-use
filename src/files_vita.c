/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "file_ops.h"
#include "json.h"
#include <psp2/io/stat.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>
#include <string.h>

int vau_vita_file_stat(void *context, const char *path, struct vau_file_info *out)
{
	(void)context;

	char current[VAU_PATH_MAX];
	size_t length = strlen(path);

	if (length >= sizeof(current))
		return VAU_INVALID;

	memcpy(current, path, length + 1);

	SceIoStat stat = { 0 };

	/* Reject link traversal instead of following a path into private data.
	 * Each prefix is bounded by the already normalized 512-byte path. */
	for (size_t i = 0; i <= length; i++) {
		if (current[i] != '/' && current[i] != 0)
			continue;

		char saved = current[i];

		current[i] = 0;

		int rc = sceIoGetstat(current, &stat);

		current[i] = saved;
		if (rc < 0)
			return rc;
		if (SCE_S_ISLNK(stat.st_mode))
			return VAU_DENIED;
		if (saved && !SCE_S_ISDIR(stat.st_mode))
			return VAU_INVALID;
	}

	if (stat.st_size < 0)
		return VAU_DEVICE_ERROR;

	*out = (struct vau_file_info){ .bytes       = (uint64_t)stat.st_size,
		                           .mode        = stat.st_mode,
		                           .attributes  = stat.st_attr,
		                           .kind        = SCE_S_ISREG(stat.st_mode)   ? VAU_FILE_REGULAR
		                                          : SCE_S_ISDIR(stat.st_mode) ? VAU_FILE_DIRECTORY
		                                                                      : VAU_FILE_OTHER,
		                           .year        = stat.st_mtime.year,
		                           .month       = stat.st_mtime.month,
		                           .day         = stat.st_mtime.day,
		                           .hour        = stat.st_mtime.hour,
		                           .minute      = stat.st_mtime.minute,
		                           .second      = stat.st_mtime.second,
		                           .microsecond = stat.st_mtime.microsecond };
	return VAU_OK;
}

/* The service serializes native I/O. Keep one directory cursor rather than
 * reopening and rescanning its entire prefix for each small transport reply. */
static struct {
	int fd;
	uint32_t position;
	int pending;
	SceIoDirent entry;
	char path[VAU_PATH_MAX];
	uint64_t used_us;
	struct vau_file_info directory;
} listing = { .fd = -1 };

static uint64_t listing_clock;

int vau_vita_file_list_reset(void)
{
	int fd = listing.fd;

	if (fd < 0)
		return VAU_OK;

	memset(&listing, 0, sizeof(listing));
	listing.fd = -1;
	return fd < 0 ? VAU_OK : sceIoDclose(fd);
}

void vau_vita_file_list_idle(uint64_t now)
{
	listing_clock = now;
	if (listing.fd >= 0 && (now < listing.used_us || now - listing.used_us >= UINT64_C(30000000)))
		(void)vau_vita_file_list_reset();
}

int vau_vita_file_list(void *context, const char *path, uint32_t offset, struct vau_file_page *out)
{
	struct vau_file_info directory;
	int rc = vau_vita_file_stat(context, path, &directory);

	if (rc < 0)
		return rc;
	if (directory.kind != VAU_FILE_DIRECTORY)
		return VAU_INVALID;
	if (!offset) {
		rc = vau_vita_file_list_reset();
		if (rc < 0)
			return rc;

		int fd = sceIoDopen(path);

		if (fd < 0)
			return fd;

		listing.fd        = fd;
		listing.directory = directory;
		memcpy(listing.path, path, strlen(path) + 1);
	} else if (listing.fd < 0 || strcmp(listing.path, path) || listing.position != offset) {
		/* An expired/interleaved traversal must restart from0, never silently
		 * resume against a different directory ordering or rescan billions. */
		return VAU_STALE;
	}

	if (offset) {
		const struct vau_file_info *old = &listing.directory;

		if (old->bytes != directory.bytes || old->mode != directory.mode ||
		    old->attributes != directory.attributes || old->year != directory.year ||
		    old->month != directory.month || old->day != directory.day ||
		    old->hour != directory.hour || old->minute != directory.minute ||
		    old->second != directory.second || old->microsecond != directory.microsecond) {
			(void)vau_vita_file_list_reset();
			return VAU_STALE;
		}
	}

	listing.used_us = listing_clock;

	uint32_t reads    = 0;
	size_t json_bytes = 0;

	out->next_offset = offset;
	for (;;) {
		if (out->count == VAU_FILE_PAGE_ENTRIES || reads == VAU_FILE_LIST_SCAN_READS) {
			out->more = 1;
			rc        = 0;
			break;
		}

		SceIoDirent *entry = &listing.entry;

		if (!listing.pending) {
			memset(entry, 0, sizeof(*entry));
			++reads;
			rc = sceIoDread(listing.fd, entry);
			if (rc <= 0)
				break;
			if (!memchr(entry->d_name, 0, sizeof(entry->d_name))) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
				continue;

			listing.pending = 1;
		}

		if (listing.position == UINT32_MAX) {
			rc = VAU_BUSY;
			break;
		}

		char child[VAU_PATH_MAX], normalized[VAU_PATH_MAX];
		size_t a = strlen(path), b = strlen(entry->d_name);
		int visible = b && a + b + 2 <= sizeof(child) && !strchr(entry->d_name, '/');

		if (visible) {
			memcpy(child, path, a);
			if (child[a - 1] != ':')
				child[a++] = '/';
			memcpy(child + a, entry->d_name, b + 1);
			visible = !vau_path_normalize(child, normalized, sizeof(normalized)) &&
			          vau_policy_file(VAU_FS_READ, normalized) == VAU_POLICY_ALLOW &&
			          !SCE_S_ISLNK(entry->d_stat.st_mode);
		}

		if (visible) {
			if (entry->d_stat.st_size < 0) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			char quoted[1533];
			int encoded = vau_json_quote(entry->d_name, quoted, sizeof(quoted));

			if (encoded < 0) {
				visible = 0;
			} else {
				size_t cost = (size_t)encoded + 128u;

				if (json_bytes + cost > VAU_FILE_PAGE_JSON_BYTES) {
					out->more = 1;
					rc        = 0;
					break;
				}

				json_bytes += cost;
			}
		}

		++listing.position;
		listing.pending  = 0;
		out->next_offset = listing.position;
		if (!visible)
			continue;

		struct vau_file_entry *dst = &out->entries[out->count++];

		memcpy(dst->name, entry->d_name, b + 1);
		dst->info = (struct vau_file_info){ .bytes       = (uint64_t)entry->d_stat.st_size,
			                                .mode        = entry->d_stat.st_mode,
			                                .attributes  = entry->d_stat.st_attr,
			                                .kind        = SCE_S_ISREG(entry->d_stat.st_mode)
			                                                       ? VAU_FILE_REGULAR
			                                               : SCE_S_ISDIR(entry->d_stat.st_mode)
			                                                       ? VAU_FILE_DIRECTORY
			                                                       : VAU_FILE_OTHER,
			                                .year        = entry->d_stat.st_mtime.year,
			                                .month       = entry->d_stat.st_mtime.month,
			                                .day         = entry->d_stat.st_mtime.day,
			                                .hour        = entry->d_stat.st_mtime.hour,
			                                .minute      = entry->d_stat.st_mtime.minute,
			                                .second      = entry->d_stat.st_mtime.second,
			                                .microsecond = entry->d_stat.st_mtime.microsecond };
	}

	if (rc < 0 || !out->more) {
		int closed = vau_vita_file_list_reset();

		if (rc >= 0 && closed < 0)
			rc = closed;
	}

	return rc < 0 ? rc : VAU_OK;
}

int vau_vita_file_read(void *context, const char *path, uint64_t offset, void *buffer,
                       uint32_t capacity, struct vau_file_chunk *out)
{
	struct vau_file_info before;
	int rc = vau_vita_file_stat(context, path, &before);

	if (rc < 0)
		return rc;
	if (before.kind != VAU_FILE_REGULAR || offset > before.bytes)
		return VAU_INVALID;

	int fd = sceIoOpen(path, SCE_O_RDONLY, 0);

	if (fd < 0)
		return fd;

	SceIoStat opened = { 0 }, after = { 0 };

	rc = sceIoGetstatByFd(fd, &opened);
	if (rc >= 0 && (!SCE_S_ISREG(opened.st_mode) || opened.st_size < 0 ||
	                (uint64_t)opened.st_size != before.bytes ||
	                memcmp(&opened.st_mtime,
	                       &(SceDateTime){ before.year, before.month, before.day, before.hour,
	                                       before.minute, before.second, before.microsecond },
	                       sizeof(SceDateTime)))) {
		rc = VAU_STALE;
	}

	if (rc >= 0) {
		SceOff position = sceIoLseek(fd, (SceOff)offset, SCE_SEEK_SET);

		if (position < 0)
			rc = (int)position;
		else if ((uint64_t)position != offset)
			rc = VAU_DEVICE_ERROR;
	}

	uint32_t count     = 0;
	uint64_t remaining = before.bytes - offset;
	uint32_t wanted    = remaining < capacity ? (uint32_t)remaining : capacity;

	while (rc >= 0 && count < wanted) {
		int read = sceIoRead(fd, (unsigned char *)buffer + count, wanted - count);

		if (read < 0)
			rc = read;
		else if (!read || (uint32_t)read > wanted - count)
			rc = VAU_STALE;
		else
			count += (uint32_t)read;
	}

	if (rc >= 0) {
		rc = sceIoGetstatByFd(fd, &after);
		if (rc >= 0 && (after.st_size != opened.st_size || after.st_mode != opened.st_mode ||
		                memcmp(&after.st_mtime, &opened.st_mtime, sizeof(SceDateTime)))) {
			rc = VAU_STALE;
		}
	}

	int closed = sceIoClose(fd);

	if (rc >= 0 && closed < 0)
		rc = closed;
	if (rc < 0)
		return rc;

	*out = (struct vau_file_chunk){ .file_bytes = before.bytes, .count = count, .info = before };
	return VAU_OK;
}
