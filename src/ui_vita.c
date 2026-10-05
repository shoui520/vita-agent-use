/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ui_vita.h"
#include "dialog_vita.h"

extern unsigned char vauPafMainQueue[];
extern void vauPafPostJob(void *queue, const char *name, void (*callback)(void *), void *context);

int vau_ui_post(struct vau_ui_job *job)
{
	if (!job)
		return VAU_INVALID;
	if (atomic_load_explicit(&job->state, memory_order_acquire) != VAU_UI_QUEUED)
		return VAU_STALE;
	if (job->posted)
		return VAU_BUSY;

	job->posted = 1;
	vauPafPostJob(vauPafMainQueue, "vita-agent-ui", vau_ui_job_dispatch, job);

	/* Means the call returned, not that the user has seen a dialog. */
	return VAU_OK;
}

static struct vau_ui_job stop_notice_job;
static unsigned stop_notice_initialized;

static int show_stopped(void *context)
{
	(void)context;
	return vau_dialog_agent_stopped();
}

int vau_ui_agent_stopped(void *context)
{
	(void)context;
	if (!stop_notice_initialized) {
		vau_ui_job_init(&stop_notice_job);
		stop_notice_initialized = 1;
	}

	int result;

	if (vau_ui_job_result(&stop_notice_job, &result) == VAU_OK) {
		(void)vau_ui_job_reset(&stop_notice_job);
		return result;
	}

	if (atomic_load_explicit(&stop_notice_job.state, memory_order_acquire) != VAU_UI_IDLE)
		return VAU_BUSY;

	int rc = vau_ui_job_prepare(&stop_notice_job, show_stopped, NULL);

	if (rc < 0)
		return rc;

	rc = vau_ui_post(&stop_notice_job);
	if (rc < 0 && !stop_notice_job.posted) {
		(void)vau_ui_job_rejected(&stop_notice_job);
		(void)vau_ui_job_reset(&stop_notice_job);
		return rc;
	}

	return VAU_BUSY;
}
