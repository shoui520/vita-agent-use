/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "timeline.h"
#include <string.h>
#include <limits.h>
#include <stddef.h>

_Static_assert(sizeof(VauPad) == 8, "pad ABI");
_Static_assert(sizeof(VauEvent) == 12, "event ABI");
_Static_assert(sizeof(VauSequence) == 40, "sequence ABI");
_Static_assert(sizeof(VauStatus) == 80, "status ABI");
_Static_assert(sizeof(VauTouchState) == 100, "touch state ABI");
_Static_assert(sizeof(struct vau_touch_pose) - offsetof(struct vau_touch_pose, enabled) ==
                       sizeof(VauTouchState),
               "touch state copy ABI");

static int active(const struct vau_timeline *t)
{
	return t->status.state == VAU_QUEUED || t->status.state == VAU_RUNNING;
}

static int lease_valid(const struct vau_timeline *t, uint64_t now)
{
	return t->leased && now < t->lease_until;
}

void vau_timeline_init(struct vau_timeline *t)
{
	memset(t, 0, sizeof(*t));
	t->events        = t->event_banks[0];
	t->touch_events  = t->touch_banks[0];
	t->status.size   = sizeof(t->status);
	t->status.abi    = VAU_ABI;
	t->status.pad.lx = t->status.pad.ly = 128;
	t->status.pad.rx = t->status.pad.ry = 128;
}

int vau_timeline_acquire(struct vau_timeline *t, uint64_t now)
{
	if (t->inhibited || t->stopped)
		return VAU_DENIED;

	/* Expired leases must be reaped by tick/release before reuse. */
	if (t->leased || active(t) || t->process_lost)
		return VAU_BUSY;
	if (now > UINT64_MAX - VAU_LEASE_US)
		return VAU_INVALID;

	t->leased                = 1;
	t->lease_until           = now + VAU_LEASE_US;
	t->status.lease_until_us = t->lease_until;
	t->expected_process      = 0;
	return VAU_OK;
}

int vau_timeline_acquire_process(struct vau_timeline *t, int process, int observed,
                                 int observation_error, uint64_t now)
{
	if (process <= 0)
		return VAU_INVALID;
	if (observation_error < 0)
		return observation_error;
	if (process != observed)
		return VAU_STALE;

	int rc = vau_timeline_acquire(t, now);

	if (rc >= 0)
		t->expected_process = process;
	return rc;
}

int vau_timeline_heartbeat(struct vau_timeline *t, uint64_t now)
{
	if (t->inhibited || t->stopped)
		return VAU_DENIED;
	if (!lease_valid(t, now))
		return VAU_EXPIRED;
	if (now > UINT64_MAX - VAU_LEASE_US)
		return VAU_INVALID;

	t->lease_until           = now + VAU_LEASE_US;
	t->status.lease_until_us = t->lease_until;
	return VAU_OK;
}

static int valid_sequence(const VauSequence *s, const VauEvent *e, uint64_t now, int continuation)
{
	if (!s || !e || s->size != sizeof(*s) || s->abi != VAU_ABI || !s->request_id || !s->count ||
	    s->count > VAU_MAX_EVENTS || !s->duration_us || s->duration_us > VAU_MAX_DURATION_US ||
	    !s->repeats || s->repeats > VAU_MAX_REPEATS || !s->max_lateness_us ||
	    s->max_lateness_us > 1000000u || s->start_us < now ||
	    (!continuation && s->start_us - now > VAU_LEASE_US) ||
	    s->start_us > UINT64_MAX - (uint64_t)s->duration_us * s->repeats) {
		return 0;
	}

	for (uint32_t i = 0; i < s->count; ++i) {
		if (e[i].at_us >= s->duration_us || (i && e[i].at_us <= e[i - 1].at_us) ||
		    (!i && e[i].at_us) || (e[i].pad.buttons & ~VAU_BUTTON_MASK)) {
			return 0;
		}
	}

	return 1;
}

static int submit(struct vau_timeline *t, const VauSequence *s, const VauEvent *events,
                  const VauTouchState *touch, const struct vau_touch_panel panels[2], uint64_t now,
                  int validate_only)
{
	if (t->inhibited || t->stopped)
		return VAU_DENIED;
	if (!lease_valid(t, now))
		return VAU_EXPIRED;
	if (!s || !events)
		return VAU_INVALID;

	/* Retries with the retained ID acknowledge the existing execution, even
	 * after completion. A changed payload with the same ID is rejected. */
	if (s->request_id && s->request_id == t->sequence.request_id) {
		if (memcmp(s, &t->sequence, sizeof(*s)) ||
		    memcmp(events, t->events, t->sequence.count * sizeof(*events)) ||
		    !!touch != t->has_touch ||
		    (touch && memcmp(touch, t->touch_events, t->sequence.count * sizeof(*touch)))) {
			return VAU_STALE;
		}

		return VAU_OK;
	}

	if (active(t))
		return VAU_BUSY;
	if (!valid_sequence(s, events, now, 0))
		return VAU_INVALID;
	if (touch) {
		if (!panels)
			return VAU_INVALID;

		struct vau_touch_pose pose = { .until_us = 1, .process = t->expected_process };

		for (uint32_t i = 0; i < s->count; i++) {
			memcpy(&pose.enabled, &touch[i], sizeof(*touch));
			if (vau_touch_pose_validate(&pose, panels) < 0)
				return VAU_INVALID;
		}
	}

	if (validate_only)
		return VAU_OK;
	if (touch)
		memcpy(t->touch_events, touch, s->count * sizeof(*touch));
	t->has_touch   = !!touch;
	t->touch_index = 0;
	t->sequence    = *s;
	memcpy(t->events, events, s->count * sizeof(*events));
	t->status.state      = VAU_QUEUED;
	t->status.error      = 0;
	t->status.request_id = s->request_id;
	t->status.started_us = t->status.last_applied_us = 0;
	t->status.iteration = t->status.next_event = t->status.applied_events = 0;
	t->status.max_lateness_us                                             = 0;
	return VAU_OK;
}

int vau_timeline_enqueue(struct vau_timeline *t, const VauSequence *s, const VauEvent *events,
                         const VauTouchState *touch, const struct vau_touch_panel panels[2],
                         uint64_t now, int validate_only)
{
	if (t->inhibited || t->stopped || !t->expected_process || t->process_lost)
		return VAU_DENIED;
	if (!lease_valid(t, now))
		return VAU_EXPIRED;
	if (!s || !events || s->start_us || !s->request_id)
		return VAU_INVALID;

	VauSequence next = *s;

	if (s->request_id == t->sequence.request_id) {
		next.start_us = t->sequence.start_us;
		return memcmp(&next, &t->sequence, sizeof(next)) || !!touch != t->has_touch ||
		                       memcmp(events, t->events, t->sequence.count * sizeof(*events)) ||
		                       (touch &&
		                        memcmp(touch, t->touch_events, t->sequence.count * sizeof(*touch)))
		               ? VAU_STALE
		               : VAU_OK;
	}

	if (t->queued && s->request_id == t->queued_sequence.request_id) {
		next.start_us = t->queued_sequence.start_us;
		return memcmp(&next, &t->queued_sequence, sizeof(next)) || !!touch != t->queued_has_touch ||
		                       memcmp(events, t->event_banks[t->bank ^ 1],
		                              t->queued_sequence.count * sizeof(*events)) ||
		                       (touch && memcmp(touch, t->touch_banks[t->bank ^ 1],
		                                        t->queued_sequence.count * sizeof(*touch)))
		               ? VAU_STALE
		               : VAU_OK;
	}

	if (t->queued)
		return VAU_BUSY;
	if (!active(t))
		return VAU_STALE;

	next.start_us = t->sequence.start_us + (uint64_t)t->sequence.duration_us * t->sequence.repeats;
	if (!valid_sequence(&next, events, now, 1))
		return VAU_INVALID;
	if (touch) {
		if (!panels)
			return VAU_INVALID;

		struct vau_touch_pose pose = { .until_us = 1, .process = t->expected_process };

		for (uint32_t i = 0; i < next.count; ++i) {
			memcpy(&pose.enabled, &touch[i], sizeof(*touch));
			if (vau_touch_pose_validate(&pose, panels) < 0)
				return VAU_INVALID;
		}
	}

	if (validate_only)
		return VAU_OK;

	unsigned bank = t->bank ^ 1;

	memcpy(t->event_banks[bank], events, next.count * sizeof(*events));
	if (touch)
		memcpy(t->touch_banks[bank], touch, next.count * sizeof(*touch));
	t->queued_sequence  = next;
	t->queued_has_touch = !!touch;
	t->queued           = 1;
	return VAU_OK;
}

int vau_timeline_submit(struct vau_timeline *t, const VauSequence *s, const VauEvent *events,
                        uint64_t now)
{
	return submit(t, s, events, NULL, NULL, now, 0);
}

int vau_timeline_submit_touch(struct vau_timeline *t, const VauSequence *s, const VauEvent *events,
                              const VauTouchState *touch, const struct vau_touch_panel panels[2],
                              uint64_t now)
{
	return touch ? submit(t, s, events, touch, panels, now, 0) : VAU_INVALID;
}

int vau_timeline_validate_touch(struct vau_timeline *t, const VauSequence *s,
                                const VauEvent *events, const VauTouchState *touch,
                                const struct vau_touch_panel panels[2], uint64_t now)
{
	return touch ? submit(t, s, events, touch, panels, now, 1) : VAU_INVALID;
}

const VauTouchState *vau_timeline_current_touch(const struct vau_timeline *t)
{
	return t->has_touch && active(t) && t->touch_index < t->sequence.count
	               ? &t->touch_events[t->touch_index]
	               : NULL;
}

int vau_timeline_touch_pose(const struct vau_timeline *t, uint64_t now, uint64_t changed,
                            struct vau_touch_pose *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	const VauTouchState *touch = vau_timeline_current_touch(t);

	if (!touch)
		return VAU_INVALID;
	if (!lease_valid(t, now))
		return VAU_EXPIRED;
	if (t->inhibited || t->stopped)
		return VAU_DENIED;
	if (changed > now)
		return VAU_STALE;

	uint64_t base = t->sequence.start_us + (uint64_t)t->status.iteration * t->sequence.duration_us;
	unsigned next = t->touch_index + 1;
	uint64_t boundary =
	        base + (next < t->sequence.count ? t->events[next].at_us : t->sequence.duration_us);
	uint64_t until =
	        now > UINT64_MAX - VAU_TOUCH_REFRESH_US ? UINT64_MAX : now + VAU_TOUCH_REFRESH_US;

	if (until > t->lease_until)
		until = t->lease_until;
	if (until > boundary)
		until = boundary;
	if (until <= now)
		return VAU_LATE;

	out->changed_us   = changed;
	out->refreshed_us = now;
	out->until_us     = until;
	out->process      = t->expected_process;
	memcpy(&out->enabled, touch, sizeof(*touch));
	return VAU_OK;
}

static int finish(struct vau_timeline *t, uint32_t state, int error, vau_apply_pad apply,
                  void *context)
{
	t->queued = 0;

	int rc = apply(context, NULL);

	t->status.state = rc < 0 ? VAU_FAILED : state;
	t->status.error = rc < 0 ? rc : error;
	if (rc >= 0) {
		memset(&t->status.pad, 0, sizeof(t->status.pad));
		t->status.pad.lx = t->status.pad.ly = 128;
		t->status.pad.rx = t->status.pad.ry = 128;
	}

	return rc < 0 ? rc : error;
}

int vau_timeline_check_process(struct vau_timeline *t, int observed, int observation_error,
                               uint64_t now, vau_apply_pad apply, void *context)
{
	if (!t->expected_process || (!t->leased && !t->process_lost))
		return VAU_OK;
	if (!t->process_lost && observation_error >= 0 && observed == t->expected_process)
		return VAU_OK;

	/* Never resume an old sequence if routing returns to the original PID. */
	t->process_lost          = 1;
	t->leased                = 0;
	t->lease_until           = 0;
	t->status.lease_until_us = 0;
	t->status.now_us         = now;
	return finish(t, VAU_FAILED, observation_error < 0 ? observation_error : VAU_STALE, apply,
	              context);
}

int vau_timeline_tick(struct vau_timeline *t, uint64_t now, vau_apply_pad apply, void *context)
{
	t->status.now_us = now;
	if (t->leased && now >= t->lease_until) {
		t->leased                = 0;
		t->status.lease_until_us = 0;
		return finish(t, VAU_LEASE_EXPIRED, VAU_EXPIRED, apply, context);
	}

	if (!active(t) || now < t->sequence.start_us)
		return VAU_OK;

	uint64_t base = t->sequence.start_us + (uint64_t)t->status.iteration * t->sequence.duration_us;

	if (t->status.next_event == t->sequence.count) {
		uint64_t end = base + t->sequence.duration_us;

		if (now < end)
			return VAU_OK;
		if (++t->status.iteration == t->sequence.repeats) {
			if (!t->queued)
				return finish(t, VAU_FINISHED, 0, apply, context);

			/* Pointer swap only: no large copy or neutral release on the
			 * timed boundary. The first continuation state applies below. */
			t->bank ^= 1;
			t->events            = t->event_banks[t->bank];
			t->touch_events      = t->touch_banks[t->bank];
			t->sequence          = t->queued_sequence;
			t->has_touch         = t->queued_has_touch;
			t->queued            = 0;
			t->touch_index       = 0;
			t->status.request_id = t->sequence.request_id;
			t->status.state      = VAU_QUEUED;
			t->status.error      = 0;
			t->status.iteration = t->status.applied_events = t->status.max_lateness_us = 0;
			t->status.started_us = t->status.last_applied_us = 0;
		}

		base                 = end;
		t->status.next_event = 0;
	}

	uint32_t i   = t->status.next_event;
	uint64_t due = base + t->events[i].at_us;

	if (now < due)
		return VAU_OK;

	uint64_t late = now - due;

	/* Do not burst stale press/release transitions after a stall or resume. */
	if (late > t->sequence.max_lateness_us ||
	    (i + 1 < t->sequence.count && now >= base + t->events[i + 1].at_us) ||
	    now >= base + t->sequence.duration_us) {
		return finish(t, VAU_FAILED, VAU_LATE, apply, context);
	}

	t->touch_index = i;

	int rc = apply(context, &t->events[i].pad);

	if (rc < 0)
		return finish(t, VAU_FAILED, rc, apply, context);

	t->status.pad = t->events[i].pad;
	if (t->status.state == VAU_QUEUED)
		t->status.started_us = now;
	t->status.state           = VAU_RUNNING;
	t->status.last_applied_us = now;
	if (late > t->status.max_lateness_us)
		t->status.max_lateness_us = (uint32_t)late;
	++t->status.next_event;
	++t->status.applied_events;
	return VAU_OK;
}

int vau_timeline_cancel(struct vau_timeline *t, uint64_t now, vau_apply_pad apply, void *context)
{
	t->status.now_us = now;
	return finish(t, VAU_CANCELLED, 0, apply, context);
}

int vau_timeline_release(struct vau_timeline *t, uint64_t now, vau_apply_pad apply, void *context)
{
	t->leased                = 0;
	t->status.lease_until_us = 0;

	int rc = vau_timeline_cancel(t, now, apply, context);

	if (rc >= 0) {
		t->expected_process = 0;
		t->process_lost     = 0;
	}

	return rc;
}

int vau_timeline_inhibit(struct vau_timeline *t, int enabled, uint64_t now, vau_apply_pad apply,
                         void *context)
{
	if (enabled != 0 && enabled != 1)
		return VAU_INVALID;
	if (!enabled && !t->inhibited)
		return VAU_OK;

	/* Block acquisition before attempting release. Failure leaves the gate
	 * closed; the trusted UI must not display an approval prompt until release
	 * succeeds. Closing the prompt never resumes an earlier macro/lease. */
	t->inhibited = 1;

	int rc = vau_timeline_release(t, now, apply, context);

	if (rc >= 0) {
		t->inhibited    = enabled;
		t->status.error = enabled ? VAU_DENIED : 0;
	}

	return rc;
}

int vau_timeline_stop(struct vau_timeline *t, uint64_t now, vau_apply_pad apply, void *context)
{
	t->stopped = 1;

	/* Exhaustion stays closed rather than letting an old decision match. */
	if (t->stop_generation < UINT64_MAX)
		++t->stop_generation;
	return vau_timeline_release(t, now, apply, context);
}

int vau_timeline_rearm(struct vau_timeline *t, uint64_t generation, uint64_t now,
                       vau_apply_pad apply, void *context)
{
	if (!t->stopped || !generation || generation != t->stop_generation)
		return VAU_STALE;
	if (t->inhibited || generation == UINT64_MAX)
		return VAU_DENIED;

	int rc = vau_timeline_release(t, now, apply, context);

	if (rc >= 0)
		t->stopped = 0;
	return rc;
}

uint32_t vau_timeline_wait_us(const struct vau_timeline *t, uint64_t now)
{
	uint64_t due = UINT64_MAX;

	if (t->leased)
		due = t->lease_until;
	if (active(t)) {
		uint64_t event =
		        t->sequence.start_us + (uint64_t)t->status.iteration * t->sequence.duration_us;

		event += t->status.next_event < t->sequence.count ? t->events[t->status.next_event].at_us
		                                                  : t->sequence.duration_us;
		if (event < due)
			due = event;
	}

	if (due <= now)
		return 1;
	return due - now > 100000u ? 100000u : (uint32_t)(due - now);
}
