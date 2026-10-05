/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_NOTIFICATION_WORKER_H
#define VAU_NOTIFICATION_WORKER_H

#include "service.h"
#include "notification.h"
#include "ui_job.h"

struct vau_notification_worker {
	struct vau_ui_job job;       /* Atomic handoff; dispatched by our own thread. */
	struct vau_service *service; /* Owner-only; notification thread never reads it. */
	struct vau_stop_bridge bridge;
	atomic_uint stopping, exited;
	uint64_t kernel_generation, queued_us, expires_us, pending_handle;
	uint64_t announced[VAU_AUTH_SLOTS], activity_us[VAU_AUTH_SLOTS];
	unsigned last_slot;

	void (*observer)(int, int); /* Owner-only diagnostic publication. */
	char name[VAU_AGENT_NAME_BYTES];
	size_t name_length;
	int event, thread, initialized, started, error, last_result, exit_result;
};

/* Resident storage/code; call once for a new object. Shared native notification
 * modules must already be loaded and stay resident. Creates an idle event-driven
 * user thread (8 KiB stack); does not send a popup or alter service authorization.
 * The stop bridge status callback/context must support concurrent reads and remain
 * resident until join; the native syscall bridge satisfies the API shape. */
int vau_notification_worker_init(struct vau_notification_worker *worker,
                                 struct vau_service *service);

/* Local authorized activation path only, serialized with service calls. Label is
 * validated presentation metadata. Live CONTROL grant required; duplicate handle
 * is suppressed. A new activation while delivery is pending returns BUSY. */
int vau_notification_worker_queue(struct vau_notification_worker *worker, uint64_t handle,
                                  const char *name, size_t length, uint64_t now_us);
void vau_notification_worker_activity(void *, uint64_t, const char *, uint64_t);

/* Owner calls after service stop/expiry polling even while idle. Cancels queued
 * notices whose grant expired/revoked and collects native acceptance/errors.
 * In-flight native RPC cannot be withdrawn; it never controls authorization. */
int vau_notification_worker_poll(struct vau_notification_worker *worker, uint64_t now_us);

/* Requests cooperative exit and waits at most 1 us per call. BUSY means still
 * resident/in flight: retry later, never free storage/unload code/kill the thread.
 * Failed resource deletion also retains ownership for cleanup retry. */
int vau_notification_worker_close(struct vau_notification_worker *worker);

#endif
