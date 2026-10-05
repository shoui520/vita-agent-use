/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "sqlite_memory.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern void *vauPafMalloc(size_t);
extern void vauPafFree(void *);
extern int sqlite3_config(int, ...);

/* Dedicated public SQLite module, used only by the serialized service worker.
 * Shell's separate SQLiteVsh instance is not reconfigured. */
#define VAU_SQLITE_MEMORY_LIMIT (512u * 1024u)

struct allocation {
	uint32_t bytes, reserved[3];
};

static unsigned allocated;

static void *allocate(int bytes)
{
	if (bytes <= 0 || (unsigned)bytes > VAU_SQLITE_MEMORY_LIMIT - sizeof(struct allocation) ||
	    allocated > VAU_SQLITE_MEMORY_LIMIT - sizeof(struct allocation) - (unsigned)bytes) {
		return NULL;
	}

	struct allocation *p = vauPafMalloc((size_t)bytes + sizeof(*p));

	if (!p)
		return NULL;

	p->bytes = (unsigned)bytes;
	allocated += (unsigned)bytes + sizeof(*p);
	return p + 1;
}

static void release(void *memory)
{
	if (!memory)
		return;

	struct allocation *p = (struct allocation *)memory - 1;

	allocated -= p->bytes + sizeof(*p);
	vauPafFree(p);
}

static int allocation_size(void *memory)
{
	return memory ? (int)(((struct allocation *)memory - 1)->bytes) : 0;
}

static void *resize(void *memory, int bytes)
{
	if (!bytes) {
		release(memory);
		return NULL;
	}

	void *next = allocate(bytes);

	if (!next)
		return NULL;
	if (memory) {
		unsigned old = (unsigned)allocation_size(memory);

		memcpy(next, memory, old < (unsigned)bytes ? old : (unsigned)bytes);
		release(memory);
	}

	return next;
}

static int roundup(int bytes)
{
	return bytes > 0 && (unsigned)bytes <= VAU_SQLITE_MEMORY_LIMIT - 7 ? (bytes + 7) & ~7 : 0;
}

static int initialize(void *context)
{
	(void)context;
	return 0;
}

static void shutdown(void *context)
{
	(void)context;
}

struct sqlite_memory_methods {
	void *(*malloc)(int);
	void (*free)(void *);
	void *(*realloc)(void *, int);
	int (*size)(void *), (*roundup)(int), (*init)(void *);
	void (*shutdown)(void *);

	void *context;
};

int vau_sqlite_memory_configure(void)
{
	static unsigned configured;
	if (configured)
		return 0;

	static const struct sqlite_memory_methods methods = { allocate,        release, resize,
		                                                  allocation_size, roundup, initialize,
		                                                  shutdown,        NULL };
	int rc = sqlite3_config(4, &methods); /* SQLITE_CONFIG_MALLOC, before first open */
	if (!rc)
		configured = 1;
	return rc;
}
