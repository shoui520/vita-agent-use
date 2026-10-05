/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_media.h"
#include "content_media_catalog.h"
#include "native_ops.h"
#include <string.h>

void vau_media_music_init(struct vau_media_music *s, void *context,
                          int (*mount)(void *, int, char *), int (*unmount)(void *, const char *))
{
	memset(s, 0, sizeof(*s));
	s->context = context;
	s->mount   = mount;
	s->unmount = unmount;
}

int vau_media_music_open(struct vau_media_music *s)
{
	if (!s || !s->mount || !s->unmount)
		return VAU_INVALID;
	if (s->busy || s->active)
		return VAU_BUSY;

	s->busy = 1;

	char point[16] = { 0 };
	int rc         = s->mount(s->context, 105, point);

	if (!rc || (uint32_t)rc == UINT32_C(0x80800003)) {
		s->active = 1;
		s->owned  = !rc;

		/* The actual 3.65 AppMgr type105 has fixed music0: identity. A borrowed
		 * mount need not populate the output. Never trust an alternate output
		 * as a path to authorize; preserve the fixed owned target for cleanup. */
		memcpy(s->point, "music0:", 8);
		if (!rc && memcmp(point, s->point, 8))
			rc = VAU_DEVICE_ERROR;
		else
			rc = 0;
	}

	s->busy = 0;
	return rc;
}

int vau_media_music_close(struct vau_media_music *s)
{
	if (!s)
		return VAU_INVALID;
	if (s->busy)
		return VAU_BUSY;
	if (!s->active)
		return 0;

	s->busy = 1;

	int rc = s->owned ? s->unmount(s->context, s->point) : 0;

	if (!rc) {
		s->active = s->owned = 0;
		memset(s->point, 0, sizeof(s->point));
	}

	s->busy = 0;
	return rc;
}

void vau_media_loopback_init(struct vau_media_loopback *s, void *context,
                             int (*drm)(void *, char *),
                             int (*mount)(void *, int, const char *, char *),
                             int (*unmount)(void *, const char *))
{
	memset(s, 0, sizeof(*s));
	s->context     = context;
	s->drm_context = drm;
	s->mount       = mount;
	s->unmount     = unmount;
}

static size_t media_loopback_point_bytes(const char *point)
{
	size_t n = 0;

	while (n < 16 && point[n])
		n++;
	if (n < 2 || n == 16 || point[n - 1] != ':')
		return 0;

	for (size_t i = 0; i + 1 < n; i++) {
		if (!((point[i] >= 'a' && point[i] <= 'z') || (point[i] >= 'A' && point[i] <= 'Z') ||
		      (point[i] >= '0' && point[i] <= '9') || point[i] == '_')) {
			return 0;
		}
	}

	return n;
}

int vau_media_loopback_open(struct vau_media_loopback *s, const char *path)
{
	if (!s || !path || !s->drm_context || !s->mount || !s->unmount)
		return VAU_INVALID;

	size_t bytes = 0;

	while (bytes < 1024 && path[bytes])
		bytes++;
	if (bytes <= 6 || bytes == 1024 || memcmp(path, "empr0:", 6))
		return VAU_INVALID;
	if (s->busy || s->active)
		return VAU_BUSY;

	s->busy = 1;

	char drm[33] = { 0 };
	int rc       = s->drm_context(s->context, drm);

	if (!rc) {
		if (drm[32])
			rc = VAU_DEVICE_ERROR;
		for (unsigned i = 0; !rc && i < 32; i++)
			if (!((drm[i] >= '0' && drm[i] <= '9') || (drm[i] >= 'A' && drm[i] <= 'F')))
				rc = VAU_DEVICE_ERROR;
	}

	if (!rc) {
		memset(s->point, 0, sizeof(s->point));
		rc = s->mount(s->context, 600, drm, s->point);
		if (!rc || (uint32_t)rc == UINT32_C(0x80800003)) {
			s->active = 1;
			s->owned  = !rc;

			size_t n = media_loopback_point_bytes(s->point), tail = bytes - 6;

			if (!n || n + tail >= sizeof(s->path)) {
				rc = VAU_DEVICE_ERROR;
			} else {
				memcpy(s->path, s->point, n);
				memcpy(s->path + n, path + 6, tail + 1);
				rc = 0;
			}
		}
	}

	s->busy = 0;
	return rc;
}

const char *vau_media_loopback_path(const struct vau_media_loopback *s)
{
	return s && s->active && !s->busy && s->path[0] ? s->path : NULL;
}

int vau_media_loopback_close(struct vau_media_loopback *s)
{
	if (!s)
		return VAU_INVALID;
	if (s->busy)
		return VAU_BUSY;
	if (!s->active)
		return 0;

	s->busy = 1;

	/* Never call unmount with malformed native output or invent a mount label. */
	int rc = s->owned ? media_loopback_point_bytes(s->point) ? s->unmount(s->context, s->point)
	                                                         : VAU_DEVICE_ERROR
	                  : 0;

	if (!rc) {
		s->active = s->owned = 0;
		memset(s->point, 0, sizeof(s->point));
		memset(s->path, 0, sizeof(s->path));
	}

	s->busy = 0;
	return rc;
}

int vau_content_media_operation_path(unsigned category, const char *path, char *out,
                                     size_t capacity)
{
	if (!out || !capacity)
		return VAU_INVALID;

	out[0] = 0;
	if (category < 1 || category > 3 || !path)
		return VAU_INVALID;

	size_t bytes = 0;

	while (bytes < 1024 && path[bytes])
		bytes++;
	if (!bytes)
		return VAU_INVALID;
	if (bytes == 1024)
		return VAU_UNSUPPORTED;

	size_t prefix      = category == 2 && bytes >= 11 && !memcmp(path, "ux0:/music/", 11) ? 11 : 0;
	size_t replacement = prefix ? 8 : 0;

	if (bytes - prefix + replacement >= capacity)
		return VAU_UNSUPPORTED;
	if (prefix)
		memcpy(out, "music0:/", replacement);
	memcpy(out + replacement, path + prefix, bytes - prefix + 1);
	return 0;
}

int vau_content_media_path_resolve(void *context, int (*native)(void *, char *, char *, int),
                                   const char *path, struct vau_content_media_path *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!path || !native)
		return VAU_INVALID;

	size_t bytes = 0;

	while (bytes < VAU_PATH_MAX && path[bytes])
		bytes++;
	if (!bytes || bytes == VAU_PATH_MAX)
		return VAU_INVALID;

	/* The 3.65 syscall copies at most 292 input bytes and requires termination.
	 * Never ask it to silently shorten a metadata path. */
	if (bytes >= 292)
		return VAU_UNSUPPORTED;

	char input[292], output[292] = { 0 };

	memcpy(input, path, bytes + 1);

	struct vau_content_media_path found = { 0 };

	if (vau_path_normalize(path, found.physical, sizeof(found.physical)))
		return VAU_INVALID;

	int rc = native(context, input, output, sizeof(output));

	if (rc)
		return rc;
	if (!output[0] || !memchr(output, 0, sizeof(output)) ||
	    vau_path_normalize(output, found.physical, sizeof(found.physical))) {
		return VAU_DEVICE_ERROR;
	}

	memcpy(found.logical, path, bytes + 1);
	*out = found;
	return 0;
}

static uint32_t media_temp_u32(const unsigned char *p)
{
	return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int vau_media_temp_directory_read(void *context, vau_memory_read read, uintptr_t start,
                                  uintptr_t end, struct vau_media_temp_directory *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	uintptr_t address = 0;
	int rc = vau_module_variable(context, read, start, end, 0x4943bf26, 0xbdcb4423, &address);
	unsigned char value[4];

	if (!rc)
		rc = read(context, address, value, sizeof(value));
	if (rc)
		return rc;

	uintptr_t pointer                     = media_temp_u32(value);
	struct vau_media_temp_directory found = { 0 };

	if (!pointer) {
		strcpy(found.path, "ur0:temp/sqlite");
	} else {
		found.overridden = 1;

		size_t i = 0;

		for (; i < sizeof(found.path); i++) {
			if (pointer > UINT32_MAX - i)
				return VAU_DEVICE_ERROR;

			rc = read(context, pointer + i, found.path + i, 1);
			if (rc)
				return rc;
			if (!found.path[i])
				break;
		}

		if (!i || i == sizeof(found.path))
			return VAU_DEVICE_ERROR;
	}

	rc = read(context, address, value, sizeof(value));
	if (rc)
		return rc;
	if (media_temp_u32(value) != pointer)
		return VAU_STALE;

	*out = found;
	return 0;
}

int vau_content_media_record_valid(const struct vau_content_media_record *r)
{
	return r && r->id && r->id <= INT64_MAX && r->category >= 1 && r->category <= 3 &&
	       r->bytes_known <= 1 && r->bytes <= INT64_MAX && (r->bytes_known || !r->bytes) &&
	       r->path[0] && memchr(r->path, 0, sizeof(r->path));
}

int vau_content_media_record_same(const struct vau_content_media_record *a,
                                  const struct vau_content_media_record *b)
{
	return vau_content_media_record_valid(a) && vau_content_media_record_valid(b) &&
	       a->id == b->id && a->category == b->category && a->status == b->status &&
	       a->bytes_known == b->bytes_known && (!a->bytes_known || a->bytes == b->bytes) &&
	       memchr(a->path, 0, sizeof(a->path)) && memchr(b->path, 0, sizeof(b->path)) &&
	       !strcmp(a->path, b->path);
}
