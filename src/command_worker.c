/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "command_worker.h"
#include "notification_worker.h"
#include <string.h>

static void trace(struct vau_command_worker *w, unsigned stage, int result, int detail)
{
	if (w->trace &&
	    (stage != w->trace_stage || result != w->trace_result || detail != w->trace_detail)) {
		w->trace_stage  = stage;
		w->trace_result = result;
		w->trace_detail = detail;
		w->trace(stage, result, detail);
	}
}

/* Session-owned work (log watches, pushed performance, the run tag and any
 * native approval) belongs to the grant, not to one TCP connection. It is
 * released only once the session ends or its peer stays away for the grace. */
static void release_sessions(struct vau_command_worker *w)
{
	for (unsigned i = 0; i < VAU_AUTH_SLOTS; i++) {
		struct vau_session *session = &w->service->auth.entries[i].session;

		for (unsigned j = 0; j < 4; j++) {
			if (session->log_ids[j]) {
				char result[3500];

				if (w->api->log_watch) {
					(void)w->api->log_watch(w->api->context, session->subject, 2, NULL, NULL,
					                        session->log_ids[j], result, sizeof(result));
				}

				session->log_ids[j] = 0;
			}
		}

		session->perf_push = 0;
		if (session->run_id[0]) {
			strcpy(session->run_phase, "connection_lost");
			session->run_id[0] = 0;
		}
	}

	if (w->api->approval_cancel)
		w->api->approval_cancel(w->api->context);
}

static int disconnect(struct vau_command_worker *w)
{
	trace(w, 5, w->driver.error, w->client.error);
	if (w->connected && !w->disconnected_us)
		w->disconnected_us = w->api->clock(w->api->context);
	if (w->connected)
		vau_tls_driver_close(&w->driver, w->driver.error);
	w->connected = 0;

	int rc = vau_net_waiter_detach(&w->waiter);

	if (rc >= 0)
		vau_net_close(&w->client);
	return rc;
}

/* A Wi-Fi reconnect invalidates every socket (SCE_NET_ERROR_EIPADDRCHANGED),
 * the listener included. Grants are not tied to a socket, so drop the dead
 * ones, keep every session and listen again; the PC then resumes the same
 * session once the network returns. */
static int network_reset(struct vau_command_worker *w, uint64_t now)
{
	trace(w, 10, w->client.error ? w->client.error : w->listener.error, w->waiter.error);
	if (w->connected) {
		trace(w, 5, w->driver.error, w->client.error);
		if (!w->disconnected_us)
			w->disconnected_us = now;
		vau_tls_driver_close(&w->driver, w->driver.error);
		w->connected = 0;
	}

	/* Destroying the epoll instance drops interest it could not detach, after
	 * which the socket may be closed. */
	if (vau_net_waiter_detach(&w->waiter) < 0 && vau_net_waiter_close(&w->waiter) < 0)
		return VAU_DEVICE_ERROR;

	vau_net_close(&w->client);
	vau_net_close(&w->listener);

	/* The first reset reopens at once; repeats back off to bound the log. */
	if (w->resets && now - w->reset_us >= VAU_WORKER_RESET_QUIET_US)
		w->resets = 0;

	unsigned shift = w->resets < 3 ? w->resets : 3;

	w->relisten_us = now + (shift ? VAU_WORKER_RELISTEN_US << (shift - 1) : 0);
	w->reset_us    = now;
	if (w->resets < 3)
		++w->resets;
	return VAU_OK;
}

int vau_command_worker_close(struct vau_command_worker *w, int error)
{
	if (!w || !w->initialized)
		return VAU_INVALID;

	w->running = 0;
	w->error   = error;

	/* Release watches while sessions still name them; stopping wipes them. */
	release_sessions(w);
	w->disconnected_us = 0;
	if (!w->service->auth.stopped)
		vau_auth_stop(&w->service->auth);
	if (w->notifications)
		(void)vau_notification_worker_poll(w->notifications, w->api->clock(w->api->context));

	int rc = disconnect(w);

	trace(w, 6, error, w->waiter.error);

	/* A physical stop may already have wiped the sessions that referenced
	 * watch slots. Every session has ended here, so free all of them. */
	if (w->api->log_watch) {
		char result[3500];

		(void)w->api->log_watch(w->api->context, "", 3, NULL, NULL, 0, result, sizeof(result));
	}

	int closed = vau_net_waiter_close(&w->waiter);

	if (closed < 0)
		rc = closed;
	/* Never close a descriptor while a failed detach/destroy retains interest.
	 * Keeping it owned lets a later close retry finish in the correct order. */
	if (w->waiter.fd != w->client.fd || w->waiter.id < 0)
		vau_net_close(&w->client);
	if (w->waiter.fd != w->listener.fd || w->waiter.id < 0)
		vau_net_close(&w->listener);
	if (w->service->input.initialized) {
		int input = vau_input_owner_poll(&w->service->input, &w->service->auth);

		if (input < 0)
			rc = input;
	}

	if (rc < 0)
		w->error = rc;
	return rc;
}

static int live_grant(const struct vau_service *s, uint64_t now)
{
	for (unsigned i = 0; i < VAU_AUTH_SLOTS; i++)
		if (s->auth.entries[i].handle && now < s->auth.entries[i].expires_us)
			return 1;
	return 0;
}

int vau_command_worker_init(struct vau_command_worker *w, struct vau_service *s,
                            const struct vau_native_api *api, struct vau_tls_server *server,
                            uint16_t port)
{
	if (!w || !s || !api || !api->clock || !server || !server->ready || server->pairing || !port)
		return VAU_INVALID;

	memset(w, 0, sizeof(*w));
	w->service     = s;
	w->api         = api;
	w->server      = server;
	w->initialized = 1;
	w->port        = port;
	vau_net_socket_init(&w->listener);
	vau_net_socket_init(&w->client);
	vau_net_waiter_init(&w->waiter);

	int rc = vau_service_transport_poll(s);

	if (rc >= 0 && !live_grant(s, api->clock(api->context)))
		rc = VAU_EXPIRED;
	if (rc >= 0)
		rc = vau_net_waiter_open(&w->waiter);
	if (rc >= 0)
		rc = vau_net_listen(&w->listener, port);
	if (rc < 0) {
		(void)vau_command_worker_close(w, rc);
		return rc;
	}

	w->last_us        = api->clock(api->context);
	w->next_accept_us = w->last_us;
	w->generation     = s->auth.stop_generation;
	w->running        = 1;
	return VAU_OK;
}

int vau_command_worker_attach_notifications(struct vau_command_worker *w,
                                            struct vau_notification_worker *notifications)
{
	if (!w || !w->initialized || !w->running || w->notifications || !notifications ||
	    !notifications->initialized || !notifications->started ||
	    notifications->service != w->service ||
	    atomic_load_explicit(&notifications->stopping, memory_order_acquire) ||
	    atomic_load_explicit(&notifications->exited, memory_order_acquire)) {
		return VAU_DENIED;
	}

	w->notifications = notifications;
	return VAU_OK;
}

static int fail(struct vau_command_worker *w, int error)
{
	(void)vau_command_worker_close(w, error);
	return error;
}

static int recover_network(struct vau_command_worker *w, uint64_t now)
{
	return network_reset(w, now) < 0 ? fail(w, VAU_DEVICE_ERROR) : VAU_OK;
}

static int pause_until(struct vau_command_worker *w, uint64_t now, uint64_t until)
{
	uint64_t remaining = until - now;
	int rc             = vau_net_pause(remaining < VAU_WORKER_WAIT_US ? (unsigned)remaining
	                                                                  : VAU_WORKER_WAIT_US);

	return rc < 0 ? fail(w, rc) : VAU_OK;
}

int vau_command_worker_step(struct vau_command_worker *w)
{
	if (!w || !w->running)
		return VAU_DENIED;

	uint64_t now  = w->api->clock(w->api->context);
	int available = vau_service_poll(w->service);

	/* Native content work must be observed even when stop ends this session. */
	if (w->api->approval_poll)
		w->api->approval_poll(w->api->context);
	if (now < w->last_us || w->service->auth.stopped ||
	    w->generation != w->service->auth.stop_generation) {
		return fail(w, VAU_DENIED);
	}

	w->last_us = now;

	/* Once every transient grant expires/revokes, return ownership to the
	 * saved-peer listener. Persistent consent is kept on disk; this is not a
	 * physical stop or a request to pair the PC again. */
	if (!live_grant(w->service, now))
		return fail(w, VAU_EXPIRED);
	if (available < 0) {
		int detail = w->service->stop.observation_error;

		if (!w->monitor_paused || available != w->monitor_result || detail != w->monitor_detail)
			trace(w, 7, available, detail);
		w->monitor_paused = 1;
		w->monitor_result = available;
		w->monitor_detail = detail;
	}

	if (available >= 0 && w->monitor_paused) {
		w->monitor_paused = 0;
		trace(w, 8, 0, 0);
	}

	if (w->notifications)
		(void)vau_notification_worker_poll(w->notifications, now);
	if (!w->connected && w->disconnected_us && now - w->disconnected_us >= VAU_SESSION_GRACE_US) {
		release_sessions(w);
		w->disconnected_us = 0;
		trace(w, 12, 0, 0);
	}

	if (!w->connected) {
		trace(w, 1, 0, 0);
		if (w->listener.fd < 0 || w->waiter.id < 0) {
			if (now < w->relisten_us)
				return pause_until(w, now, w->relisten_us);

			/* Retry each second while the network is still down. */
			w->relisten_us = now + VAU_WORKER_RELISTEN_US;
			if (w->waiter.id < 0 && vau_net_waiter_open(&w->waiter) < 0)
				return VAU_OK;
			if (w->listener.fd < 0 && vau_net_listen(&w->listener, w->port) < 0)
				return VAU_OK;
			trace(w, 11, 0, 0);
			return VAU_OK;
		}
		if (now < w->next_accept_us)
			return pause_until(w, now, w->next_accept_us);

		int ready = vau_net_wait(&w->waiter, &w->listener, 0, VAU_WORKER_WAIT_US);

		if (ready < 0)
			return recover_network(w, now);
		if (!ready)
			return VAU_OK;
		if (!live_grant(w->service, w->api->clock(w->api->context)))
			return fail(w, VAU_EXPIRED);
		if (vau_service_transport_poll(w->service) < 0) {
			if (w->service->auth.stopped)
				return fail(w, VAU_DENIED);
			return VAU_OK;
		}

		int rc = vau_net_accept(&w->listener, &w->client);

		if (rc == 1)
			return VAU_OK;
		if (rc < 0)
			return recover_network(w, now);

		now = w->api->clock(w->api->context);
		if (now < w->last_us || now > UINT64_MAX - VAU_WORKER_ADMISSION_US)
			return fail(w, VAU_DEVICE_ERROR);

		w->last_us        = now;
		w->next_accept_us = now + VAU_WORKER_ADMISSION_US;
		if (vau_net_waiter_detach(&w->waiter) < 0)
			return recover_network(w, now);
		if (vau_tls_server_reset(w->server) < 0)
			return fail(w, VAU_DEVICE_ERROR);

		mbedtls_ssl_set_bio(&w->server->channel, &w->client, vau_net_send, vau_net_recv, NULL);
		rc = vau_tls_driver_init(&w->driver, &w->server->channel, w->service, now);
		if (rc < 0)
			return fail(w, rc);

		w->connected = 1;
		return VAU_OK;
	}

	trace(w,
	      !w->driver.active                                      ? 2
	      : w->driver.connection.state == VAU_CONNECTION_READING ? 3
	                                                             : 4,
	      0, 0);

	struct vau_connection *c = &w->driver.connection;

	/* A served request proves the peer came back within the grace. */
	if (w->disconnected_us && w->driver.active && c->requests)
		w->disconnected_us = 0;

	/* Only the paired PC holds this listener's certificate, so a waiting
	 * connection while the current one has gone silent means that PC lost the
	 * old one without the Vita seeing it close. Hand over instead of making it
	 * wait for the idle limit. */
	if (w->driver.active && c->state == VAU_CONNECTION_READING && !c->request.used &&
	    now >= c->last_rx_us && now - c->last_rx_us >= VAU_WORKER_PREEMPT_US &&
	    now >= w->preempt_check_us) {
		w->preempt_check_us = now + VAU_WORKER_ADMISSION_US;

		int waiting = vau_net_wait(&w->waiter, &w->listener, 0, 0);

		if (waiting < 0)
			return recover_network(w, now);
		if (waiting > 0) {
			trace(w, 9, 0, 0);
			if (disconnect(w) < 0)
				return recover_network(w, now);
			return VAU_OK;
		}
	}
	if (w->driver.work == VAU_TLS_WAIT_READ || w->driver.work == VAU_TLS_WAIT_WRITE) {
		int ready = vau_net_wait(&w->waiter, &w->client, w->driver.work == VAU_TLS_WAIT_WRITE,
		                         VAU_WORKER_WAIT_US);

		if (ready < 0)
			return recover_network(w, now);

		now = w->api->clock(w->api->context);
		if (now < w->last_us)
			return fail(w, VAU_DEVICE_ERROR);

		w->last_us = now;
	}

	if (!live_grant(w->service, now))
		return fail(w, VAU_EXPIRED);
	if (vau_tls_driver_step(&w->driver, w->service, w->api, now) == VAU_TLS_CLOSED) {
		if (disconnect(w) < 0)
			return recover_network(w, now);
	}

	return VAU_OK;
}
