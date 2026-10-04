/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ui_job.h"
_Static_assert(ATOMIC_INT_LOCK_FREE==2,"UI handoff requires lock-free word atomics");
void vau_ui_job_init(struct vau_ui_job *j)
{
    j->execute=0; j->context=0; j->result=VAU_BUSY; j->posted=0;
    atomic_init(&j->state,VAU_UI_IDLE);
}
int vau_ui_job_prepare(struct vau_ui_job *j,int (*execute)(void *),void *context)
{
    if (!j || !execute) return VAU_INVALID;
    if (atomic_load_explicit(&j->state,memory_order_acquire)!=VAU_UI_IDLE) return VAU_BUSY;
    j->execute=execute; j->context=context; j->result=VAU_BUSY; j->posted=0;
    atomic_store_explicit(&j->state,VAU_UI_QUEUED,memory_order_release);
    return VAU_OK;
}
int vau_ui_job_cancel(struct vau_ui_job *j)
{
    if (!j) return VAU_INVALID;
    unsigned expected=VAU_UI_QUEUED;
    if (atomic_compare_exchange_strong_explicit(&j->state,&expected,VAU_UI_CANCEL_PENDING,
            memory_order_acq_rel,memory_order_acquire)) return VAU_OK;
    if (expected==VAU_UI_CANCEL_PENDING) return VAU_OK;
    return expected==VAU_UI_RUNNING ? VAU_BUSY : VAU_STALE;
}
void vau_ui_job_dispatch(void *context)
{
    struct vau_ui_job *j=context;
    if (!j) return;
    unsigned expected=VAU_UI_QUEUED;
    if (atomic_compare_exchange_strong_explicit(&j->state,&expected,VAU_UI_RUNNING,
            memory_order_acq_rel,memory_order_acquire)) j->result=j->execute(j->context);
    else if (expected==VAU_UI_CANCEL_PENDING) j->result=VAU_DENIED;
    else return;
    atomic_store_explicit(&j->state,VAU_UI_DONE,memory_order_release);
}
int vau_ui_job_result(struct vau_ui_job *j,int *result)
{
    if (!j || !result) return VAU_INVALID;
    if (atomic_load_explicit(&j->state,memory_order_acquire)!=VAU_UI_DONE) return VAU_BUSY;
    *result=j->result;
    return VAU_OK;
}
int vau_ui_job_reset(struct vau_ui_job *j)
{
    if (!j) return VAU_INVALID;
    if (atomic_load_explicit(&j->state,memory_order_acquire)!=VAU_UI_DONE) return VAU_BUSY;
    j->execute=0; j->context=0; j->result=VAU_BUSY;
    atomic_store_explicit(&j->state,VAU_UI_IDLE,memory_order_release);
    return VAU_OK;
}
int vau_ui_job_rejected(struct vau_ui_job *j)
{
    if (!j) return VAU_INVALID;
    unsigned state=atomic_load_explicit(&j->state,memory_order_acquire);
    if (state!=VAU_UI_QUEUED && state!=VAU_UI_CANCEL_PENDING) return VAU_STALE;
    j->result=VAU_DEVICE_ERROR;
    atomic_store_explicit(&j->state,VAU_UI_DONE,memory_order_release);
    return VAU_OK;
}
