/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_UI_JOB_H
#define VAU_UI_JOB_H
#include <stdatomic.h>
#include "vita_agent.h"
enum vau_ui_job_state { VAU_UI_IDLE, VAU_UI_QUEUED, VAU_UI_RUNNING,
                        VAU_UI_CANCEL_PENDING, VAU_UI_DONE };
struct vau_ui_job {
    atomic_uint state;
    int (*execute)(void *context);
    void *context;
    int result;
    unsigned posted; /* Worker-owned: prevent retaining the same job twice. */
};
/* One worker owns prepare/cancel/result/reset, serialized with its service.
 * The UI queue calls dispatch exactly once per successful enqueue. Storage
 * and context must remain alive until DONE, even after cancellation. DONE
 * releases data ownership, NOT executable code: keep the module resident.
 * A running action cannot be cancelled here; it must check its service/stop
 * generation itself and arrange native UI cleanup when necessary. */
void vau_ui_job_init(struct vau_ui_job *job);
int vau_ui_job_prepare(struct vau_ui_job *job,int (*execute)(void *),void *context);
int vau_ui_job_cancel(struct vau_ui_job *job);
void vau_ui_job_dispatch(void *job);
int vau_ui_job_result(struct vau_ui_job *job,int *result);
int vau_ui_job_reset(struct vau_ui_job *job);
/* Only after the queue explicitly guarantees it never retained the callback.
 * Never use for a timeout or an enqueue API with an unknown outcome. */
int vau_ui_job_rejected(struct vau_ui_job *job);
#endif
