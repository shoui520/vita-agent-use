/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "service.h"
#include "format.h"
#include <string.h>

void vau_service_init(struct vau_service *s, const struct vau_stop_bridge *bridge)
{
	memset(s, 0, sizeof(*s));
	if (bridge)
		s->bridge = *bridge;
	vau_auth_init(&s->auth);
	vau_auth_stop(&s->auth); /* First activation requires local approval. */
}

static int poll_stop(struct vau_service *s)
{
	if (!s)
		return VAU_INVALID;

	VauStopStatus status = { 0 };
	int rc = s->bridge.status ? s->bridge.status(s->bridge.context, &status) : VAU_UNSUPPORTED;

	s->valid = rc >= 0 && status.size == sizeof(status) && status.abi == VAU_ABI &&
	           status.stopped <= 1 && status.ready <= 1 && status.chord_held <= 1 &&
	           (!status.stopped || status.generation != 0);
	if (!s->valid) {
		if (!s->fault || !s->auth.stopped)
			vau_auth_stop(&s->auth);
		s->fault = 1;
		return rc < 0 ? rc : VAU_DEVICE_ERROR;
	}

	int changed = s->observed && status.generation != s->stop.generation;

	if (changed && status.stopped)
		s->stop_notice_pending = 1;
	s->observed = 1;
	s->stop     = status;

	int fault = !status.ready || status.observation_error;

	/*
	 * A missed sample is temporary availability, not a physical stop or a
	 * loss of saved trust. Grants are revoked (and the local generation bumped)
	 * when:
	 *
	 *   - the kernel stop generation moved, even if the chord was already released;
	 *   - sampling just faulted while stopped, voiding any approval on screen;
	 *   - a stop or held chord is seen while grants are still live.
	 */
	if (changed || (fault && !s->fault && s->auth.stopped) ||
	    ((status.stopped || status.chord_held) && !s->auth.stopped)) {
		vau_auth_stop(&s->auth);
	}

	s->fault = fault;
	if (fault && !s->auth.stopped && s->input.initialized && s->input.handle) {
		int released = vau_input_owner_release(&s->input, &s->auth, s->input.handle);

		if (released < 0)
			return released;
	}

	if (!status.ready || status.stopped || status.chord_held || status.observation_error)
		return VAU_DENIED;
	return s->auth.stopped ? VAU_DENIED : VAU_OK;
}

int vau_service_attach_input(struct vau_service *s, const struct vau_input_bridge *bridge)
{
	if (!s || !s->auth.stopped || s->input.initialized)
		return VAU_DENIED;
	return vau_input_owner_init(&s->input, bridge);
}

int vau_service_poll(struct vau_service *s)
{
	int rc = poll_stop(s);

	if (s && s->input.initialized) {
		int input_rc = vau_input_owner_poll(&s->input, &s->auth);

		if (input_rc < 0)
			return input_rc;
	}

	if (s && s->stop_notice_pending && s->stop_notice && s->valid && !s->approval_pending &&
	    (!s->input.initialized || (!s->input.cleanup && !s->input.handle))) {
		int notice = s->stop_notice(s->stop_notice_context);

		if (notice != VAU_BUSY)
			s->stop_notice_pending = 0;
	}

	return rc;
}

int vau_service_transport_poll(struct vau_service *s)
{
	int rc = vau_service_poll(s);

	if (rc >= 0)
		return rc;
	return s && s->valid && !s->auth.stopped && !s->stop.stopped && !s->stop.chord_held ? VAU_OK
	                                                                                    : rc;
}

int vau_service_rearm(struct vau_service *s, uint64_t local, uint64_t kernel)
{
	if (!s)
		return VAU_INVALID;

	(void)vau_service_poll(s);
	if (!s->valid || !s->stop.ready || s->stop.chord_held || s->stop.observation_error)
		return VAU_DENIED;
	if (local != s->auth.stop_generation || kernel != s->stop.generation)
		return VAU_STALE;
	if (!s->auth.stopped)
		return VAU_STALE;
	if (s->stop.stopped) {
		if (!s->bridge.rearm)
			return VAU_UNSUPPORTED;

		int rc = s->bridge.rearm(s->bridge.context, kernel);

		if (rc < 0)
			return rc;
	}

	/* A stop racing kernel rearm must invalidate this local approval. */
	(void)vau_service_poll(s);
	if (!s->valid || !s->stop.ready || s->stop.stopped || s->stop.chord_held ||
	    s->stop.observation_error) {
		return VAU_DENIED;
	}

	if (kernel != s->stop.generation)
		return VAU_STALE;
	return vau_auth_rearm(&s->auth, local);
}

int vau_service_grant(struct vau_service *s, unsigned rights, uint64_t now, uint64_t lifetime,
                      vau_entropy entropy, void *context, uint64_t *handle,
                      char token[VAU_TOKEN_HEX_BYTES + 1])
{
	if (!s || !handle || !token)
		return VAU_INVALID;

	*handle = 0;
	memset(token, 0, VAU_TOKEN_HEX_BYTES + 1);

	int rc = vau_service_poll(s);

	if (rc < 0)
		return rc;
	return vau_auth_grant(&s->auth, rights, now, lifetime, entropy, context, handle, token);
}

static int input_dispatch(void *context, uint64_t handle, enum vau_input_operation op,
                          VauStatus *status, uint64_t *lease_until)
{
	struct vau_service *s = context;

	if (!s->input.initialized)
		return VAU_UNSUPPORTED;
	if (s->approval_pending && (op == VAU_INPUT_ACQUIRE || op == VAU_INPUT_HEARTBEAT))
		return VAU_BUSY;

	int rc;

	switch (op) {
	case VAU_INPUT_ACQUIRE: rc = vau_input_owner_acquire(&s->input, &s->auth, handle); break;
	case VAU_INPUT_HEARTBEAT: rc = vau_input_owner_heartbeat(&s->input, &s->auth, handle); break;
	case VAU_INPUT_CANCEL: rc = vau_input_owner_cancel(&s->input, &s->auth, handle); break;
	case VAU_INPUT_RELEASE: rc = vau_input_owner_release(&s->input, &s->auth, handle); break;
	case VAU_INPUT_STATUS: rc = vau_input_owner_status(&s->input, &s->auth, handle, status); break;
	default: return VAU_UNSUPPORTED;
	}

	*lease_until = s->input.lease_until;
	return rc;
}

static int input_submit(void *context, uint64_t handle, const VauSequence *sequence,
                        const VauEvent *events, uint64_t *execution_id)
{
	struct vau_service *s = context;

	if (!s->input.initialized)
		return VAU_UNSUPPORTED;
	if (s->approval_pending)
		return VAU_BUSY;
	return vau_input_owner_submit(&s->input, &s->auth, handle, sequence, events, execution_id);
}

static int input_acquire_process(void *context, uint64_t handle, int32_t process,
                                 uint64_t *lease_until)
{
	struct vau_service *s = context;

	if (!s->input.initialized)
		return VAU_UNSUPPORTED;
	if (s->approval_pending)
		return VAU_BUSY;

	int rc = vau_input_owner_acquire_process(&s->input, &s->auth, handle, process);

	*lease_until = s->input.lease_until;
	return rc;
}

static int input_submit_touch(void *context, uint64_t handle, const VauSequence *sequence,
                              const VauEvent *events, const VauTouchState *touch,
                              uint64_t *execution_id)
{
	struct vau_service *s = context;

	if (!s->input.initialized)
		return VAU_UNSUPPORTED;
	if (s->approval_pending)
		return VAU_BUSY;
	return vau_input_owner_submit_touch(&s->input, &s->auth, handle, sequence, events, touch,
	                                    execution_id);
}

static int input_enqueue(void *context, uint64_t handle, const VauSequence *sequence,
                         const VauEvent *events, const VauTouchState *touch, uint64_t *execution_id)
{
	struct vau_service *s = context;

	if (!s->input.initialized)
		return VAU_UNSUPPORTED;
	if (s->approval_pending)
		return VAU_BUSY;
	return vau_input_owner_enqueue(&s->input, &s->auth, handle, sequence, events, touch,
	                               execution_id);
}

int vau_service_request(struct vau_service *s, const struct vau_native_api *api,
                        const struct vau_http_request *request, char *response, size_t capacity,
                        unsigned *http_status)
{
	if (!s || !api)
		return VAU_INVALID;

	int background = request && request->state == VAU_HTTP_READY && !request->pairing_only &&
	                 !request->frame_request && !request->file_read_request &&
	                 !request->audit_request && !request->upload_request &&
	                 vau_protocol_background_request(request->data + request->header_bytes,
	                                                 request->body_bytes);
	int available = background ? vau_service_transport_poll(s) : vau_service_poll(s);

	if (available < 0 && !s->auth.stopped) {
		if (!response || !http_status || !capacity)
			return VAU_INVALID;

		*http_status = 503;
		return vau_snprintf(response, capacity, "{\"v\":1,\"status\":\"error\",\"error_code\":%d}",
		                    available);
	}

	struct vau_native_api bound = *api;

	bound.input_context         = s;
	bound.input                 = input_dispatch;
	bound.input_submit          = input_submit;
	bound.input_acquire_process = input_acquire_process;
	bound.input_submit_touch    = input_submit_touch;
	bound.input_enqueue         = input_enqueue;
	return vau_authenticated_request(&s->auth, &bound, request, response, capacity, http_status);
}
