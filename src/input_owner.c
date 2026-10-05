/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "input_owner.h"
#include <string.h>

static int allowed(const struct vau_auth *auth, uint64_t handle, uint64_t now)
{
	if (!auth || auth->stopped || !handle)
		return 0;

	for (unsigned i = 0; i < VAU_AUTH_SLOTS; ++i) {
		const struct vau_auth_entry *e = &auth->entries[i];

		if (e->handle == handle && now < e->expires_us && (e->session.rights & VAU_RIGHT_CONTROL))
			return 1;
	}

	return 0;
}

int vau_input_owner_init(struct vau_input_owner *in, const struct vau_input_bridge *b)
{
	if (!in || !b || !b->clock || !b->acquire || !b->heartbeat || !b->submit || !b->cancel ||
	    !b->release || !b->status) {
		return VAU_INVALID;
	}

	memset(in, 0, sizeof(*in));
	in->bridge        = *b;
	in->next_sequence = 1;
	in->last_us       = b->clock(b->context);
	in->initialized   = 1;
	return VAU_OK;
}

/*
 * The cleanup flag stays set until the kernel confirms the release, so every
 * later poll retries it, and the stale handle keeps new owners out meanwhile.
 */
static int cleanup(struct vau_input_owner *in)
{
	in->cleanup = 1;

	int rc = in->bridge.release(in->bridge.context);

	if (rc >= 0) {
		in->handle      = 0;
		in->lease_until = 0;
		in->cleanup     = 0;
		in->process     = 0;
	}

	return rc;
}

int vau_input_owner_poll(struct vau_input_owner *in, const struct vau_auth *auth)
{
	if (!in || !in->initialized || !auth)
		return VAU_INVALID;

	/* A clock that ran backwards makes every lease deadline meaningless. */
	uint64_t now  = in->bridge.clock(in->bridge.context);
	int backwards = now < in->last_us;

	if (!backwards)
		in->last_us = now;
	if (in->handle &&
	    (in->cleanup || backwards || now >= in->lease_until || !allowed(auth, in->handle, now))) {
		int rc = cleanup(in);

		if (rc < 0)
			return rc;
	}

	return backwards ? VAU_DEVICE_ERROR : VAU_OK;
}

static int owner(struct vau_input_owner *in, const struct vau_auth *auth, uint64_t handle)
{
	int rc = vau_input_owner_poll(in, auth);

	if (rc < 0)
		return rc;
	if (!allowed(auth, handle, in->last_us))
		return VAU_DENIED;
	return in->handle == handle ? VAU_OK : VAU_DENIED;
}

int vau_input_owner_acquire_process(struct vau_input_owner *in, const struct vau_auth *auth,
                                    uint64_t handle, int32_t process)
{
	if (process < 0)
		return VAU_INVALID;

	int rc = vau_input_owner_poll(in, auth);

	if (rc < 0)
		return rc;
	if (!allowed(auth, handle, in->last_us))
		return VAU_DENIED;
	if (in->handle)
		return VAU_BUSY;
	if (in->last_us > UINT64_MAX - VAU_LEASE_US)
		return VAU_INVALID;
	if (process && !in->bridge.acquire_process)
		return VAU_UNSUPPORTED;

	/* The kernel keeps its own lease of the same length; either expiring ends ownership. */
	rc = process ? in->bridge.acquire_process(in->bridge.context, process)
	             : in->bridge.acquire(in->bridge.context);
	if (rc >= 0) {
		in->handle      = handle;
		in->lease_until = in->last_us + VAU_LEASE_US;
		in->process     = process;
	}

	return rc;
}

int vau_input_owner_acquire(struct vau_input_owner *in, const struct vau_auth *auth,
                            uint64_t handle)
{
	return vau_input_owner_acquire_process(in, auth, handle, 0);
}

int vau_input_owner_heartbeat(struct vau_input_owner *in, const struct vau_auth *auth,
                              uint64_t handle)
{
	int rc = owner(in, auth, handle);

	if (rc < 0)
		return rc;
	if (in->last_us > UINT64_MAX - VAU_LEASE_US)
		return VAU_INVALID;

	rc = in->bridge.heartbeat(in->bridge.context);
	if (rc >= 0)
		in->lease_until = in->last_us + VAU_LEASE_US;
	else
		(void)cleanup(in);
	return rc;
}

static int submit(struct vau_input_owner *in, const struct vau_auth *auth, uint64_t handle,
                  const VauSequence *sequence, const VauEvent *events, const VauTouchState *touch,
                  uint64_t *execution_id)
{
	if (!execution_id)
		return VAU_INVALID;

	*execution_id = 0;

	int rc = owner(in, auth, handle);

	if (rc < 0)
		return rc;
	if (!sequence || !events || !in->next_sequence)
		return VAU_INVALID;
	if (touch && !in->bridge.submit_touch)
		return VAU_UNSUPPORTED;

	/* Kernel IDs are global to this resident service, not per remote session.
	 * The command layer handles retries before this potentially effectful call. */
	VauSequence native = *sequence;

	native.request_id = in->next_sequence++;
	rc                = touch ? in->bridge.submit_touch(in->bridge.context, &native, events, touch)
	                          : in->bridge.submit(in->bridge.context, &native, events);
	if (rc >= 0)
		*execution_id = native.request_id;
	return rc;
}

int vau_input_owner_submit(struct vau_input_owner *in, const struct vau_auth *auth, uint64_t handle,
                           const VauSequence *sequence, const VauEvent *events,
                           uint64_t *execution_id)
{
	return submit(in, auth, handle, sequence, events, NULL, execution_id);
}

int vau_input_owner_submit_touch(struct vau_input_owner *in, const struct vau_auth *auth,
                                 uint64_t handle, const VauSequence *sequence,
                                 const VauEvent *events, const VauTouchState *touch,
                                 uint64_t *execution_id)
{
	if (!touch) {
		if (execution_id)
			*execution_id = 0;
		return VAU_INVALID;
	}

	return submit(in, auth, handle, sequence, events, touch, execution_id);
}

int vau_input_owner_enqueue(struct vau_input_owner *in, const struct vau_auth *auth,
                            uint64_t handle, const VauSequence *sequence, const VauEvent *events,
                            const VauTouchState *touch, uint64_t *execution_id)
{
	if (!execution_id)
		return VAU_INVALID;

	*execution_id = 0;

	int rc = owner(in, auth, handle);

	if (rc < 0)
		return rc;
	if (!in->process)
		return VAU_DENIED;
	if (!in->bridge.enqueue)
		return VAU_UNSUPPORTED;
	if (!sequence || !events || !in->next_sequence)
		return VAU_INVALID;

	VauSequence native = *sequence;

	native.request_id = in->next_sequence++;
	rc                = in->bridge.enqueue(in->bridge.context, &native, events, touch);
	if (rc >= 0)
		*execution_id = native.request_id;
	return rc;
}

int vau_input_owner_cancel(struct vau_input_owner *in, const struct vau_auth *auth, uint64_t handle)
{
	int rc = owner(in, auth, handle);

	if (rc < 0)
		return rc;

	rc = in->bridge.cancel(in->bridge.context);
	if (rc < 0)
		(void)cleanup(in);
	return rc;
}

int vau_input_owner_release(struct vau_input_owner *in, const struct vau_auth *auth,
                            uint64_t handle)
{
	int rc = owner(in, auth, handle);

	return rc < 0 ? rc : cleanup(in);
}

int vau_input_owner_status(struct vau_input_owner *in, const struct vau_auth *auth, uint64_t handle,
                           VauStatus *status)
{
	if (!status)
		return VAU_INVALID;

	memset(status, 0, sizeof(*status));

	int rc = owner(in, auth, handle);

	if (rc < 0)
		return rc;

	rc = in->bridge.status(in->bridge.context, status);
	if (rc >= 0 &&
	    (status->size != sizeof(*status) || status->abi != VAU_ABI || status->state > VAU_FAILED)) {
		rc = VAU_DEVICE_ERROR;
	}

	if (rc < 0)
		memset(status, 0, sizeof(*status));
	return rc;
}
