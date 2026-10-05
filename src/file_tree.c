/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "file_tree.h"
#include <psp2/io/dirent.h>
#include <string.h>

struct frame {
	int fd;
	unsigned length;
};

int vau_native_tree_walk(const char *root, int post, vau_tree_visit visit, void *context,
                         int (*stopped)(void *), void *stop_context)
{
	if (!root || !visit || !stopped || (post != 0 && post != 1))
		return VAU_INVALID;

	char path[VAU_PATH_MAX];

	if (vau_path_normalize(root, path, sizeof(path)))
		return VAU_INVALID;

	struct vau_file_info info;
	int rc = vau_vita_file_stat(NULL, path, &info);

	if (rc)
		return rc;
	if (stopped(stop_context))
		return VAU_DENIED;
	if (info.kind != VAU_FILE_DIRECTORY)
		return info.kind == VAU_FILE_REGULAR ? visit(context, path, &info) : VAU_DENIED;
	if (!post) {
		rc = visit(context, path, &info);
		if (rc)
			return rc;
	}

	struct frame frames[VAU_PATH_MAX / 2];
	unsigned depth = 0;
	int fd         = sceIoDopen(path);

	if (fd < 0)
		return fd;

	frames[depth++] = (struct frame){ fd, (unsigned)strlen(path) };
	while (depth) {
		if (stopped(stop_context)) {
			rc = VAU_DENIED;
			break;
		}

		struct frame *f   = &frames[depth - 1];
		SceIoDirent entry = { 0 };

		rc = sceIoDread(f->fd, &entry);
		if (rc < 0)
			break;
		if (!rc) {
			int closed = sceIoDclose(f->fd);

			f->fd = -1;
			if (closed < 0) {
				rc = closed;
				break;
			}

			if (post) {
				rc = vau_vita_file_stat(NULL, path, &info);
				if (!rc)
					rc = visit(context, path, &info);
				if (rc)
					break;
			}

			--depth;
			if (depth)
				path[frames[depth - 1].length] = 0;
			continue;
		}

		if (!memchr(entry.d_name, 0, sizeof(entry.d_name))) {
			rc = VAU_DEVICE_ERROR;
			break;
		}

		if (!strcmp(entry.d_name, ".") || !strcmp(entry.d_name, ".."))
			continue;

		size_t bytes = strlen(entry.d_name), base = f->length;

		if (!bytes || strchr(entry.d_name, '/') || base + bytes + 2 > sizeof(path)) {
			rc = VAU_INVALID;
			break;
		}

		if (path[base - 1] != ':')
			path[base++] = '/';
		memcpy(path + base, entry.d_name, bytes + 1);

		char normalized[VAU_PATH_MAX];

		if (vau_path_normalize(path, normalized, sizeof(normalized)) || strcmp(path, normalized)) {
			rc = VAU_INVALID;
			break;
		}

		rc = vau_vita_file_stat(NULL, path, &info);
		if (rc)
			break;
		if (info.kind != VAU_FILE_REGULAR && info.kind != VAU_FILE_DIRECTORY) {
			rc = VAU_DENIED;
			break;
		}

		if (!post || info.kind == VAU_FILE_REGULAR) {
			rc = visit(context, path, &info);
			if (rc)
				break;
		}

		if (info.kind == VAU_FILE_DIRECTORY) {
			if (depth == sizeof(frames) / sizeof(*frames)) {
				rc = VAU_INVALID;
				break;
			}

			fd = sceIoDopen(path);
			if (fd < 0) {
				rc = fd;
				break;
			}

			frames[depth++] = (struct frame){ fd, (unsigned)strlen(path) };
		} else {
			path[f->length] = 0;
		}
	}

	while (depth) {
		fd = frames[--depth].fd;
		if (fd >= 0) {
			int closed = sceIoDclose(fd);

			if (!rc && closed < 0)
				rc = closed;
		}
	}

	return rc;
}
