/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_media.h"
#include "native_ops.h"
#include <string.h>

#ifdef VAU_NATIVE_FORMAT
_Static_assert(sizeof(struct vau_media_sdk_owner) == 12, "native content owner ABI");
_Static_assert(sizeof(struct vau_media_sdk_ids) == 12, "native content vector ABI");
_Static_assert(sizeof(struct vau_media_sdk_string) == 8, "native content string ABI");
#endif
void vau_media_sdk_init(struct vau_media_sdk *s, const struct vau_content_sdk_loader *loader,
                        void *context, void *(*allocate)(void *, size_t),
                        void (*release)(void *, void *))
{
	memset(s, 0, sizeof(*s));
	if (loader)
		s->loader = *loader;
	s->memory_context = context;
	s->allocate       = allocate;
	s->release        = release;
}

static int media_sdk_bind(struct vau_media_sdk *s)
{
	if (s->bound)
		return VAU_OK;
	if (!s->loader.loaded || !s->loader.load || !s->loader.resolve || !s->allocate || !s->release)
		return VAU_INVALID;

	int rc = s->loader.loaded(s->loader.context);

	if (rc == 1)
		rc = s->loader.load(s->loader.context);
	if (rc)
		return rc;

	const uint32_t nids[]  = { 0x668cb1e5, 0xaf89df37, 0x1a67467d, 0x70b406bd };
	uintptr_t addresses[4] = { 0 };

	for (unsigned i = 0; i < 4; i++) {
		rc = s->loader.resolve(s->loader.context, nids[i], addresses + i);
		if (rc)
			return rc;
		if (!addresses[i])
			return VAU_DEVICE_ERROR;
	}

	s->construct = (struct vau_media_sdk_owner * (*)(struct vau_media_sdk_owner *)) addresses[0];
	s->destroy   = (struct vau_media_sdk_owner * (*)(struct vau_media_sdk_owner *)) addresses[1];
	s->attach    = (int (*)(struct vau_media_sdk_owner *, void *, void *))addresses[2];
	s->remove    = (int (*)(struct vau_media_sdk_owner *, struct vau_media_sdk_ids *,
                         const struct vau_media_sdk_string *, unsigned,
                         const unsigned char *))addresses[3];
	s->bound     = 1;
	return VAU_OK;
}

int vau_media_sdk_remove(struct vau_media_sdk *s, void *database, unsigned category, uint64_t id)
{
	if (!s || !database || category < 1 || category > 3 || !id || id > INT64_MAX)
		return VAU_INVALID;
	if (s->busy)
		return VAU_BUSY;

	s->busy = 1;

	int rc = media_sdk_bind(s);

	if (rc) {
		s->busy = 0;
		return rc;
	}

	struct vau_media_sdk_ids ids = { 0 };

	ids.data = s->allocate(s->memory_context, sizeof(*ids.data));
	if (!ids.data) {
		s->busy = 0;
		return VAU_DEVICE_ERROR;
	}

	ids.data[0] = id;
	ids.count = ids.capacity = 1;

	struct vau_media_sdk_owner owner = { 0 };

	s->construct(&owner);
	if (!owner.progress || !owner.factories)
		rc = VAU_DEVICE_ERROR;
	else
		rc = s->attach(&owner, database, NULL);
	if (!rc) {
		const struct vau_media_sdk_string name = { "main", 4 };
		const unsigned char options[2]         = { category == 2 ? 0 : 1, 0 };

		rc = s->remove(&owner, &ids, &name, category, options);
	}

	/* The SDK may edit its ID vector on failure. Release its current owned
	 * buffer, not a saved pointer that native code could have replaced. */
	s->destroy(&owner);
	if (ids.data)
		s->release(s->memory_context, ids.data);
	s->busy = 0;
	return rc;
}

_Static_assert(sizeof(union vau_media_db_storage) == 184, "SceDbutil connection storage");

void vau_media_db_init(struct vau_media_db *s, const struct vau_content_sdk_loader *loader)
{
	memset(s, 0, sizeof(*s));
	if (loader)
		s->loader = *loader;
}

static int media_db_bind(struct vau_media_db *s)
{
	if (s->bound)
		return VAU_OK;
	if (!s->loader.loaded || !s->loader.load || !s->loader.resolve)
		return VAU_INVALID;

	int rc = s->loader.loaded(s->loader.context);

	if (rc == 1)
		rc = s->loader.load(s->loader.context);
	if (rc)
		return rc;

	const uint32_t nids[]  = { 0xfd7dd749, 0x453787a2, 0x56d53123, 0x4f1dcdc4, 0x593beab7 };
	uintptr_t addresses[5] = { 0 };

	for (unsigned i = 0; i < 5; i++) {
		rc = s->loader.resolve(s->loader.context, nids[i], addresses + i);
		if (rc)
			return rc;
		if (!addresses[i])
			return VAU_DEVICE_ERROR;
	}

	s->construct = (void *(*)(void *))addresses[0];
	s->destroy   = (void *(*)(void *))addresses[1];
	s->open      = (int (*)(void *, const struct vau_media_sdk_string *, uint32_t))addresses[2];
	s->close     = (int (*)(void *))addresses[3];
	s->timeout   = (int (*)(void *, int))addresses[4];
	s->bound     = 1;
	return VAU_OK;
}

static int media_db_teardown(struct vau_media_db *s)
{
	int rc = s->close(s->storage.bytes);

	s->destroy(s->storage.bytes);
	memset(&s->storage, 0, sizeof(s->storage));
	s->constructed = s->ready = 0;
	return rc;
}

int vau_media_db_open(struct vau_media_db *s, unsigned category, int writable)
{
	if (!s || category < 1 || category > 3 || (writable != 0 && writable != 1))
		return VAU_INVALID;
	if (s->busy || s->constructed)
		return VAU_BUSY;

	s->busy = 1;

	int rc = media_db_bind(s);

	if (rc) {
		s->busy = 0;
		return rc;
	}

	static const char *const paths[] = {
		"ux0:/mms/photo/AVContent.db",
		"ux0:/mms/music/AVContent.db",
		"ux0:/mms/video/AVContent.db",
	};

	const char *path                       = paths[category - 1];
	const struct vau_media_sdk_string name = { path, (uint32_t)strlen(path) };

	s->construct(s->storage.bytes);
	s->constructed = 1;
	rc             = s->open(s->storage.bytes, &name, writable ? UINT32_C(0x10000002) : 1);

	/* Bound worker contention; no service/input hook waits on this connection.
	 * Sony's setter preserves the native database error facility. */
	if (!rc)
		rc = s->timeout(s->storage.bytes, 1000);
	if (rc)
		(void)media_db_teardown(s);
	else
		s->ready = 1;
	s->busy = 0;
	return rc;
}

void *vau_media_db_context(struct vau_media_db *s)
{
	return s && s->ready && !s->busy ? s->storage.bytes : NULL;
}

int vau_media_db_close(struct vau_media_db *s)
{
	if (!s)
		return VAU_INVALID;
	if (s->busy)
		return VAU_BUSY;
	if (!s->constructed)
		return VAU_OK;

	s->busy = 1;

	int rc = media_db_teardown(s);

	s->busy = 0;
	return rc;
}

void vau_media_modules_init(struct vau_media_modules *s, void *context,
                            int (*resolve)(void *, uint32_t, uintptr_t *), int (*stopped)(void *))
{
	memset(s, 0, sizeof(*s));
	s->context = context;
	s->resolve = resolve;
	s->stopped = stopped;
}

static int media_modules_bind(struct vau_media_modules *s)
{
	if (s->bound)
		return 0;
	if (!s->resolve)
		return VAU_INVALID;

	const uint32_t nids[]  = { 0xb3b5df38, 0x7c86911e, 0xd2e471dc };
	uintptr_t addresses[3] = { 0 };

	for (unsigned i = 0; i < 3; i++) {
		int rc = s->resolve(s->context, nids[i], &addresses[i]);

		if (rc)
			return rc;
		if (!addresses[i])
			return VAU_DEVICE_ERROR;
	}

	s->acquire = (void **(*)(void **, const char *, unsigned, unsigned, void *))addresses[0];
	s->release = (void **(*)(void **))addresses[1];
	s->status  = (int (*)(void **))addresses[2];
	s->bound   = 1;
	return 0;
}

static void media_modules_teardown(struct vau_media_modules *s)
{
	while (s->count) {
		void **ref = &s->references[--s->count];

		s->release(ref);
		*ref = NULL;
	}
}

int vau_media_modules_acquire(struct vau_media_modules *s, unsigned category)
{
	if (!s || category < 1 || category > 3)
		return VAU_INVALID;
	if (s->busy || s->count)
		return VAU_BUSY;

	s->busy = 1;

	int rc = media_modules_bind(s);

	static const char *const paths[] = {
		"vs0:vsh/common/libmarlin.suprx",         "vs0:vsh/common/libFflMp4.suprx",
		"vs0:vsh/common/libSenvuabsFFsdk.suprx",  "vs0:vsh/common/libvideoprofiler.suprx",
		"vs0:vsh/common/content_operation.suprx",
	};
	for (unsigned i = category == 3 ? 0 : 4; !rc && i < 5; i++) {
		if (s->stopped && s->stopped(s->context)) {
			rc = VAU_EXPIRED;
			break;
		}

		unsigned char opaque = 0;
		void **ref           = &s->references[s->count];

		s->acquire(ref, paths[i], 0, 1, &opaque);
		if (!*ref) {
			rc = VAU_DEVICE_ERROR;
		} else {
			s->count++;
			rc = s->status(ref);
		}
	}

	if (rc)
		media_modules_teardown(s);
	s->busy = 0;
	return rc;
}

int vau_media_modules_release(struct vau_media_modules *s)
{
	if (!s)
		return VAU_INVALID;
	if (s->busy)
		return VAU_BUSY;

	s->busy = 1;
	media_modules_teardown(s);
	s->busy = 0;
	return 0;
}

/* Native 3.65 owner/list vtables. Native widths are used on the host fixture as
 * well. No guessed firmware address or suffix construction is involved. */
static uintptr_t media_related_method(void *object, unsigned slot)
{
	const uintptr_t *table;

	memcpy(&table, object, sizeof(table));
	return table ? table[slot] : 0;
}

static int media_related_stopped(struct vau_media_related *s)
{
	return s->stopped && s->stopped(s->context);
}

int vau_media_related_walk(struct vau_media_related *s, void *owner, vau_media_related_visit visit,
                           void *context)
{
	if (!s || !owner || !visit || !s->release_path)
		return VAU_INVALID;
	if (s->busy)
		return VAU_BUSY;

	uintptr_t get_address     = media_related_method(owner, 6),
	          release_address = media_related_method(owner, 7);

	if (!get_address || !release_address)
		return VAU_DEVICE_ERROR;

	int (*get)(void *, void **)    = (int (*)(void *, void **))get_address;
	int (*release)(void *, void *) = (int (*)(void *, void *))release_address;
	s->busy                        = 1;

	void *list = NULL;
	int rc     = media_related_stopped(s) ? VAU_EXPIRED : get(owner, &list);

	if (!rc && !list)
		rc = VAU_DEVICE_ERROR;
	if (!rc) {
		uintptr_t count_address = media_related_method(list, 3),
		          path_address  = media_related_method(list, 5);

		if (!count_address || !path_address) {
			rc = VAU_DEVICE_ERROR;
		} else {
			int (*count)(void *)              = (int (*)(void *))count_address;
			int (*path)(void *, int, char **) = (int (*)(void *, int, char **))path_address;

			int total = count(list);

			if (total < 0)
				rc = total;
			for (int i = 0; !rc && i < total; i++) {
				char *value = NULL;

				if (media_related_stopped(s)) {
					rc = VAU_EXPIRED;
					break;
				}

				rc = path(list, i, &value);
				if (!rc) {
					/* Native path builder accepts at most1024 allocated bytes,
					 * including terminator. Reject missing/empty/long output. */
					size_t bytes = 0;

					if (value)
						while (bytes < 1024 && value[bytes])
							bytes++;
					if (!value || !bytes || bytes == 1024)
						rc = VAU_DEVICE_ERROR;
					else if (media_related_stopped(s))
						rc = VAU_EXPIRED;
					else
						rc = visit(context, value, bytes);
				}

				/* Even failed native getters may have allocated an output. */
				if (value)
					s->release_path(s->context, value);
			}
		}
	}

	if (list) {
		int end = release(owner, list);

		if (!rc)
			rc = end;
	}

	s->busy = 0;
	return rc;
}

void vau_media_profiler_init(struct vau_media_profiler *s,
                             const struct vau_content_sdk_loader *loader, void *context,
                             void (*release)(void *, void *), int (*media_profiler_stopped)(void *))
{
	memset(s, 0, sizeof(*s));
	if (loader)
		s->loader = *loader;
	s->related = (struct vau_media_related){ context, release, media_profiler_stopped, 0 };
}

static int media_profiler_stopped(struct vau_media_profiler *s)
{
	return s->related.stopped && s->related.stopped(s->related.context);
}

static int media_profiler_bind(struct vau_media_profiler *s)
{
	if (s->bound)
		return 0;
	if (!s->loader.loaded || !s->loader.load || !s->loader.resolve)
		return VAU_INVALID;

	int rc = s->loader.loaded(s->loader.context);

	if (rc == 1)
		rc = s->loader.load(s->loader.context);
	if (rc)
		return rc;

	const uint32_t nids[]  = { 0x8417be57, 0x2dbe786b, 0x4dbb7596, 0xe5b10a6b };
	uintptr_t addresses[4] = { 0 };

	for (unsigned i = 0; i < 4; i++) {
		rc = s->loader.resolve(s->loader.context, nids[i], &addresses[i]);
		if (rc)
			return rc;
		if (!addresses[i])
			return VAU_DEVICE_ERROR;
	}

	s->memory            = (void *(*)(void))addresses[0];
	s->initialize_memory = (int (*)(void *))addresses[1];
	s->open              = (int (*)(void *, const char *, void **, unsigned char))addresses[2];
	s->close             = (int (*)(void *, void *))addresses[3];
	s->bound             = 1;
	return 0;
}

static int media_profiler_prepare(struct vau_media_profiler *s)
{
	int rc = media_profiler_stopped(s) ? VAU_EXPIRED : media_profiler_bind(s);

	if (!rc && !s->memory()) {
		/* NULL selects the native default PAF allocation context. Never install
		 * a SceDbutil connection here or replace another native user's heap. */
		rc = s->initialize_memory(NULL);
		if (!rc && !s->memory())
			rc = VAU_DEVICE_ERROR;
	}

	return rc;
}

int vau_media_profiler_prepare(struct vau_media_profiler *s)
{
	if (!s)
		return VAU_INVALID;
	if (s->busy)
		return VAU_BUSY;

	s->busy = 1;

	int rc = media_profiler_prepare(s);

	s->busy = 0;
	return rc;
}

int vau_media_profiler_walk(struct vau_media_profiler *s, const char *path,
                            vau_media_related_visit visit, void *context)
{
	if (!s || !path || !visit || !s->related.release_path)
		return VAU_INVALID;

	size_t bytes = 0;

	while (bytes < 1024 && path[bytes])
		bytes++;
	if (!bytes || bytes == 1024)
		return VAU_INVALID;
	if (s->busy)
		return VAU_BUSY;

	s->busy = 1;

	int rc               = media_profiler_prepare(s);
	unsigned char opaque = 0;
	void *owner          = NULL;

	if (!rc)
		rc = media_profiler_stopped(s) ? VAU_EXPIRED : s->open(&opaque, path, &owner, 0);
	if (!rc && !owner)
		rc = VAU_DEVICE_ERROR;
	if (!rc)
		rc = vau_media_related_walk(&s->related, owner, visit, context);
	if (owner) {
		int end = s->close(&opaque, owner);

		if (!rc)
			rc = end;
	}

	s->busy = 0;
	return rc;
}
