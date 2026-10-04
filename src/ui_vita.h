/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_UI_VITA_H
#define VAU_UI_VITA_H
#include "ui_job.h"
/* Shell 3.65 only, PAF must already be loaded. Owner calls once per prepared
 * job. Native enqueue has no verified acceptance result: do not retry, reject,
 * reset or release job storage merely because execution is delayed.
 * Module code must remain resident through native callbacks and UI ownership. */
int vau_ui_post(struct vau_ui_job *job);
/* Service-owner callback. Posts once to Shell UI and waits for job ownership
 * to return. No thread, grant, or input rearm. */
int vau_ui_agent_stopped(void *context);
#endif
