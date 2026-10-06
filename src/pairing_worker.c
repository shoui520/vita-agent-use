/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pairing_worker.h"
#include <string.h>

static int matches(const struct vau_pairing_binding *a, const struct vau_pairing_binding *b)
{
	return b && a->connection == b->connection &&
	       a->local_stop_generation == b->local_stop_generation &&
	       a->kernel_stop_generation == b->kernel_stop_generation &&
	       !memcmp(a->certificate_sha256, b->certificate_sha256, 32);
}

/* UI thread only. Even failed Open may retain native callback objects; never
 * report a terminal result until the UI confirms release of both objects. */
static int ui_step(void *context)
{
	struct vau_pairing_worker *w = context;
	uint64_t now                 = w->api->clock(w->api->context);

	if (now >= w->deadline_us || now < w->deadline_us - VAU_PAIRING_UI_TIMEOUT_US)
		atomic_store_explicit(&w->cancelled, 1, memory_order_release);
	if (w->begin_job) {
		vau_pairing_ui_init(&w->ui);
		if (atomic_load_explicit(&w->cancelled, memory_order_acquire)) {
			w->ui_finished = 1;
			return VAU_DENIED;
		}

		int rc = vau_pairing_ui_begin(&w->ui, &w->binding, w->name, w->name_length, now);

		if (w->ui.state == VAU_PAIR_UI_IDLE) {
			w->ui_finished = 1;
			return rc < 0 ? rc : VAU_DEVICE_ERROR;
		}
	}

	if (atomic_load_explicit(&w->cancelled, memory_order_acquire))
		vau_pairing_ui_cancel(&w->ui);

	int rc = vau_pairing_ui_poll(&w->ui, &w->binding, now);

	w->ui_finished = w->ui.state == VAU_PAIR_UI_DONE;
	return w->ui_finished ? rc : VAU_BUSY;
}

static int post(struct vau_pairing_worker *w)
{
	int rc = vau_ui_job_prepare(&w->job, ui_step, w);

	if (rc < 0)
		return rc;

	rc = vau_ui_post(&w->job);

	/* A pre-enqueue rejection owns no native callback. No timeout or returned
	 * success is treated as proof that the native queue has released the job. */
	if (rc < 0 && !w->job.posted) {
		(void)vau_ui_job_rejected(&w->job);
		return rc;
	}

	return VAU_OK;
}

void vau_pairing_worker_init(struct vau_pairing_worker *w, struct vau_service *s,
                             const struct vau_native_api *api,
                             struct vau_notification_worker *notifications)
{
	memset(w, 0, sizeof(*w));
	w->service       = s;
	w->api           = api;
	w->notifications = notifications;
	vau_ui_job_init(&w->job);
	atomic_init(&w->cancelled, 0);
}

int vau_pairing_worker_begin(struct vau_pairing_worker *w,
                             const struct vau_pairing_binding *current, const char *name,
                             size_t length, uint64_t now)
{
	if (!w || !w->service || !w->api || !w->api->clock || !current || !current->connection ||
	    now > UINT64_MAX - VAU_PAIRING_UI_TIMEOUT_US) {
		return VAU_INVALID;
	}

	if (w->state != VAU_PAIR_WORK_IDLE)
		return VAU_BUSY;

	uint16_t label[VAU_AGENT_NAME_BYTES];
	size_t units;
	int rc = vau_agent_name_utf16(label, &units, name, length);

	if (rc < 0)
		return rc;

	struct vau_service *s = w->service;

	(void)vau_service_poll(s);
	if (!s->auth.stopped || !s->valid || !s->stop.ready || s->stop.chord_held ||
	    s->stop.observation_error) {
		return VAU_DENIED;
	}

	if (s->auth.stop_generation != current->local_stop_generation ||
	    s->stop.generation != current->kernel_stop_generation) {
		return VAU_STALE;
	}

	if (s->input.initialized && s->input.cleanup)
		return VAU_BUSY;

	rc = vauInputSetApprovalGate(1);
	if (rc < 0)
		return rc;

	w->binding = *current;
	memcpy(w->name, name, length);
	w->name_length = length;
	w->last_us     = now;
	w->deadline_us = now + VAU_PAIRING_UI_TIMEOUT_US;
	w->begin_job   = 1;
	w->state       = VAU_PAIR_WORK_PENDING;
	w->result      = VAU_BUSY;
	rc             = post(w);
	if (rc < 0) {
		w->result = rc;
		atomic_store_explicit(&w->cancelled, 1, memory_order_release);
	}

	return rc;
}

void vau_pairing_worker_cancel(struct vau_pairing_worker *w)
{
	if (w && w->state == VAU_PAIR_WORK_PENDING)
		atomic_store_explicit(&w->cancelled, 1, memory_order_release);
}

int vau_pairing_worker_poll(struct vau_pairing_worker *w, const struct vau_pairing_binding *current,
                            uint64_t now)
{
	if (!w || w->state == VAU_PAIR_WORK_IDLE)
		return VAU_INVALID;
	if (w->state == VAU_PAIR_WORK_DONE)
		return w->result;

	struct vau_service *s = w->service;

	(void)vau_service_poll(s);
	if (!matches(&w->binding, current) || now < w->last_us || now >= w->deadline_us || !s->valid ||
	    !s->stop.ready || s->stop.chord_held || s->stop.observation_error ||
	    s->auth.stop_generation != w->binding.local_stop_generation ||
	    s->stop.generation != w->binding.kernel_stop_generation) {
		vau_pairing_worker_cancel(w);
	}

	w->last_us = now;

	int decision;

	if (vau_ui_job_result(&w->job, &decision) != VAU_OK)
		return VAU_BUSY;

	/* Acquire of job DONE releases callback-context ownership, but native UI
	 * still owns ui until ui_finished. Workers never read the UI object. */
	(void)vau_ui_job_reset(&w->job);
	if (w->ui_finished ||
	    (w->begin_job && atomic_load_explicit(&w->cancelled, memory_order_acquire) &&
	     !w->job.posted)) {
		if (atomic_load_explicit(&w->cancelled, memory_order_acquire))
			decision = VAU_DENIED;
		w->result = vau_vita_pairing_activate(s, decision, &w->binding, current, w->notifications,
		                                      w->name, w->name_length, now, &w->grant);
		w->state  = VAU_PAIR_WORK_DONE;
		return w->result;
	}

	w->begin_job = 0;

	int rc = post(w);

	if (rc < 0) {
		w->result = rc;
		vau_pairing_worker_cancel(w);
	}

	return VAU_BUSY;
}

int vau_pairing_worker_reset(struct vau_pairing_worker *w)
{
	if (!w)
		return VAU_INVALID;
	if (w->state != VAU_PAIR_WORK_DONE)
		return VAU_BUSY;

	volatile unsigned char *token = (volatile unsigned char *)&w->grant;

	for (size_t i = 0; i < sizeof(w->grant); i++)
		token[i] = 0;
	memset(&w->binding, 0, sizeof(w->binding));
	memset(w->name, 0, sizeof(w->name));
	w->name_length = 0;
	w->last_us = w->deadline_us = 0;
	w->begin_job = w->ui_finished = w->result = 0;
	w->state                                  = VAU_PAIR_WORK_IDLE;
	atomic_store_explicit(&w->cancelled, 0, memory_order_release);
	return VAU_OK;
}
