/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "event_ring.h"
#include <psp2kern/io/fcntl.h>
#include <psp2kern/kernel/threadmgr.h>
#include <taihen.h>
#include <stdatomic.h>
#include <string.h>

static struct vau_event_ring ring;
static tai_hook_ref_t open_ref, rename_ref;
static int open_id = -1, rename_id = -1;
static atomic_flag busy = ATOMIC_FLAG_INIT;
static _Atomic uint32_t enabled, dropped;

static void publish(unsigned kind, const char *path)
{
	if (!atomic_load_explicit(&enabled, memory_order_relaxed) || !vau_dump_path(path, kind))
		return;

	/* Crash handling must never wait for the network, allocate, log, or list files. */
	if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire)) {
		atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
		return;
	}

	if (vau_event_publish(&ring, kind, path, ksceKernelGetSystemTimeWide()) < 0)
		atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
	atomic_flag_clear_explicit(&busy, memory_order_release);
}

static int dump_open(const char *path, int flags, int mode)
{
	int rc = TAI_CONTINUE(int, open_ref, path, flags, mode);

	if (rc >= 0 && (flags & SCE_O_CREAT) && (flags & SCE_O_WRONLY))
		publish(VAU_DUMP_SAVING, path);
	return rc;
}

static int dump_rename(const char *from, const char *to)
{
	int rc = TAI_CONTINUE(int, rename_ref, from, to);

	if (rc >= 0 && vau_dump_path(from, VAU_DUMP_SAVING))
		publish(VAU_DUMP_COMPLETE, to);
	return rc;
}

int vau_dump_events_kernel(uint32_t operation, uint32_t after, VauDumpPage *out)
{
	if (operation > 2 || !out)
		return VAU_INVALID;
	if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire))
		return VAU_BUSY;

	int rc = VAU_OK;

	if (operation == 0) {
		/* Only SceCoredump's verified 3.65 imports, not every system IO operation.
		 * No hooks are installed during plugin start or normal boot.
		 * SceIofilemgrForDriver (0x40FD29C7): ksceIoOpen 0x75192972, ksceIoRename 0xDC0C4997. */
		if (open_id < 0) {
			open_id = taiHookFunctionImportForKernel(0x10005, &open_ref, "SceCoredump", 0x40FD29C7,
			                                         0x75192972, dump_open);
		}

		if (rename_id < 0) {
			rename_id = taiHookFunctionImportForKernel(0x10005, &rename_ref, "SceCoredump",
			                                           0x40FD29C7, 0xDC0C4997, dump_rename);
		}

		rc = open_id < 0 ? open_id : rename_id < 0 ? rename_id : VAU_OK;
		if (rc >= 0) {
			atomic_store(&enabled, 1);
			after = ring.latest;
		}
	} else if (operation == 2) {
		after = ring.latest;
	} /* Default crash capture remains enabled. */
	if (rc >= 0)
		rc = vau_event_read(&ring, after, out);
	if (rc >= 0)
		out->dropped = atomic_load(&dropped);
	atomic_flag_clear_explicit(&busy, memory_order_release);
	return rc;
}
