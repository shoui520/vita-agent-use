/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_TIMELINE_H
#define VAU_TIMELINE_H

#include "vita_agent.h"
#include "touch_sample.h"

struct vau_timeline {
	VauSequence sequence;
	VauEvent event_banks[2][VAU_MAX_EVENTS];
	VauTouchState touch_banks[2][VAU_MAX_EVENTS];
	VauEvent *events;
	VauTouchState *touch_events;
	VauSequence queued_sequence;
	unsigned bank;
	int queued, queued_has_touch;
	int has_touch;
	uint32_t touch_index;
	VauStatus status;
	uint64_t lease_until;
	uint64_t stop_generation;
	int leased, inhibited, stopped;
	int expected_process, process_lost;
};

typedef int (*vau_apply_pad)(void *context, const VauPad *pad);

/* pad==NULL releases this service's emulation slot. Caller serializes access. */
void vau_timeline_init(struct vau_timeline *t);
int vau_timeline_acquire(struct vau_timeline *t, uint64_t now);
int vau_timeline_acquire_process(struct vau_timeline *t, int process, int observed,
                                 int observation_error, uint64_t now);
int vau_timeline_check_process(struct vau_timeline *t, int observed, int observation_error,
                               uint64_t now, vau_apply_pad apply, void *context);
int vau_timeline_heartbeat(struct vau_timeline *t, uint64_t now);
int vau_timeline_submit(struct vau_timeline *t, const VauSequence *s, const VauEvent *events,
                        uint64_t now);
int vau_timeline_submit_touch(struct vau_timeline *t, const VauSequence *s, const VauEvent *events,
                              const VauTouchState *touch, const struct vau_touch_panel panels[2],
                              uint64_t now);
int vau_timeline_validate_touch(struct vau_timeline *t, const VauSequence *s,
                                const VauEvent *events, const VauTouchState *touch,
                                const struct vau_touch_panel panels[2], uint64_t now);

/* One bounded continuation for a process-bound macro. start_us must be zero;
 * the scheduler derives its exact start from the current segment's end. */
int vau_timeline_enqueue(struct vau_timeline *t, const VauSequence *s, const VauEvent *events,
                         const VauTouchState *touch, const struct vau_touch_panel panels[2],
                         uint64_t now, int validate_only);

/* Available while the apply callback submits a scheduled pad or refreshes its
 * last state. Caller still releases native touch when apply receives NULL. */
const VauTouchState *vau_timeline_current_touch(const struct vau_timeline *t);

/* Build the current event's short-lived sample, capped at its next transition,
 * repeat boundary and lease. changed is the actual event publication time. */
int vau_timeline_touch_pose(const struct vau_timeline *t, uint64_t now, uint64_t changed,
                            struct vau_touch_pose *out);
int vau_timeline_tick(struct vau_timeline *t, uint64_t now, vau_apply_pad apply, void *context);
int vau_timeline_cancel(struct vau_timeline *t, uint64_t now, vau_apply_pad apply, void *context);
int vau_timeline_release(struct vau_timeline *t, uint64_t now, vau_apply_pad apply, void *context);
int vau_timeline_inhibit(struct vau_timeline *t, int enabled, uint64_t now, vau_apply_pad apply,
                         void *context);

/* Trusted local control only. Each stop invalidates previous rearm decisions.
 * Approval-gate changes never clear this latch. The caller must revoke other
 * session capabilities as well; this scheduler only controls input. */
int vau_timeline_stop(struct vau_timeline *t, uint64_t now, vau_apply_pad apply, void *context);
int vau_timeline_rearm(struct vau_timeline *t, uint64_t generation, uint64_t now,
                       vau_apply_pad apply, void *context);
uint32_t vau_timeline_wait_us(const struct vau_timeline *t, uint64_t now);

#endif
