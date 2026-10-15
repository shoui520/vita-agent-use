/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_COMMAND_WORKER_H
#define VAU_COMMAND_WORKER_H

#include "tls_server.h"
#include "tls_driver.h"
#include "net_vita.h"

struct vau_notification_worker;
#define VAU_WORKER_WAIT_US      16000u
#define VAU_WORKER_ADMISSION_US UINT64_C(1000000)
/* A connection that has sent nothing for this long, while another waits to be
 * accepted, is presumed dead (peer slept, roamed or lost its NAT mapping). Live
 * clients heartbeat well inside it. */
#define VAU_WORKER_PREEMPT_US UINT64_C(30000000)
/* While the network is down, a dead listener is reopened this often. Resets
 * that repeat back off to 4 s apart, until the network stays quiet for 10 s. */
#define VAU_WORKER_RELISTEN_US    UINT64_C(1000000)
#define VAU_WORKER_RESET_QUIET_US UINT64_C(10000000)

struct vau_command_worker {
	struct vau_service *service;
	struct vau_notification_worker *notifications;
	const struct vau_native_api *api;
	struct vau_tls_server *server;
	struct vau_net_socket listener, client;
	struct vau_net_waiter waiter;
	struct vau_tls_driver driver;
	uint64_t last_us, next_accept_us, generation;
	uint64_t disconnected_us, preempt_check_us, relisten_us, reset_us;
	unsigned resets;
	uint16_t port;
	int initialized, running, connected, error, monitor_paused;
	int monitor_result, monitor_detail;

	void (*trace)(unsigned, int, int);

	unsigned trace_stage;
	int trace_result, trace_detail;
};

/* Worker-owned resident/heap state, not stack. Caller initializes trusted TLS
 * credentials and service/input bridge, then obtains fresh local activation.
 * Pairing/bootstrap servers are rejected. This does not load trust or grant
 * permissions. One worker owns all state and BIO/allocator calls. */
int vau_command_worker_init(struct vau_command_worker *worker, struct vau_service *service,
                            const struct vau_native_api *api, struct vau_tls_server *server,
                            uint16_t port);

/* Optional independent worker owned by the same service. Call before serving;
 * this binds only cancellation/result polling, not popup creation or ownership.
 * Runtime queues a notice from the locally authorized activation path. */
int vau_command_worker_attach_notifications(struct vau_command_worker *worker,
                                            struct vau_notification_worker *notifications);

/* One state-machine operation, with at most 16ms network wait. RUN TLS steps
 * may do native work/public-key computations exceeding that interval. Caller
 * loops while running, on a user worker with adequate stack (initially 96KiB).
 * Polls stop and lease revocation even without incoming commands. A failed
 * socket (Wi-Fi reconnect) is closed and the listener reopened; sessions keep
 * their grants. Trace stages: 10 network reset, 11 listening again, 12 the
 * disconnect grace ended and session work was released. */
int vau_command_worker_step(struct vau_command_worker *worker);

/* Stops/revokes the service, closes channel/listener and releases a frame loan.
 * TLS context ownership stays with caller; free only after socket closure.
 * Failed native cleanup may be retried by calling close again. */
int vau_command_worker_close(struct vau_command_worker *worker, int error);

#endif
