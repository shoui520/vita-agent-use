/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "notification_worker.h"
#include <psp2/kernel/threadmgr.h>
#include <string.h>
static int live(struct vau_notification_worker *w,uint64_t handle,uint64_t now)
{
    if (!handle || w->service->auth.stopped) return 0;
    for (unsigned i=0;i<VAU_AUTH_SLOTS;i++) {
        const struct vau_auth_entry *e=&w->service->auth.entries[i];
        if (e->handle==handle && now<e->expires_us && (e->session.rights&VAU_RIGHT_CONTROL)) return 1;
    }
    return 0;
}
static int deliver(void *context)
{
    struct vau_notification_worker *w=context;
    if (atomic_load_explicit(&w->stopping,memory_order_acquire)) return VAU_DENIED;
    VauStopStatus status={0};
    int rc=w->bridge.status ? w->bridge.status(w->bridge.context,&status) : VAU_UNSUPPORTED;
    if (rc<0) return rc;
    if (status.size!=sizeof(status) || status.abi!=VAU_ABI || status.ready!=1 ||
        status.stopped || status.chord_held || status.observation_error ||
        status.generation!=w->kernel_generation) return VAU_DENIED;
    int64_t now=sceKernelGetSystemTimeWide();
    if (now<0 || (uint64_t)now<w->queued_us || (uint64_t)now>=w->expires_us ||
        atomic_load_explicit(&w->stopping,memory_order_acquire)) return VAU_EXPIRED;
    return vau_vita_notification_using(w->name,w->name_length);
}
static int wait_loop(struct vau_notification_worker *w)
{
    for (;;) {
        if (atomic_load_explicit(&w->stopping,memory_order_acquire)) return VAU_OK;
        int rc=sceKernelWaitEventFlag(w->event,1,SCE_EVENT_WAITOR|SCE_EVENT_WAITCLEAR_PAT,NULL,NULL);
        if (rc<0) return rc;
        if (atomic_load_explicit(&w->stopping,memory_order_acquire)) return VAU_OK;
        vau_ui_job_dispatch(&w->job);
    }
}
static int run(SceSize size,void *args)
{
    if (size!=sizeof(struct vau_notification_worker *) || !args) return VAU_INVALID;
    struct vau_notification_worker *w;
    memcpy(&w,args,sizeof(w));
    int rc=wait_loop(w);
    w->exit_result=rc;
    atomic_store_explicit(&w->exited,1,memory_order_release);
    return rc;
}
int vau_notification_worker_close(struct vau_notification_worker *w)
{
    if (!w || !w->initialized) return VAU_INVALID;
    atomic_store_explicit(&w->stopping,1,memory_order_release);
    (void)vau_ui_job_cancel(&w->job);
    if (w->started) {
        int rc=sceKernelSetEventFlag(w->event,1);
        if (rc<0) { w->error=rc; return rc; }
        unsigned timeout=1;
        rc=sceKernelWaitThreadEnd(w->thread,NULL,&timeout);
        if (rc<0) { w->error=rc; return VAU_BUSY; }
        w->started=0;
    }
    if (w->thread>=0) {
        int rc=sceKernelDeleteThread(w->thread);
        if (rc<0) { w->error=rc; return rc; }
        w->thread=-1;
    }
    if (w->event>=0) {
        int rc=sceKernelDeleteEventFlag(w->event);
        if (rc<0) { w->error=rc; return rc; }
        w->event=-1;
    }
    return VAU_OK;
}
int vau_notification_worker_init(struct vau_notification_worker *w,struct vau_service *s)
{
    if (!w || !s || !s->bridge.status) return VAU_INVALID;
    memset(w,0,sizeof(*w));
    w->service=s; w->bridge=s->bridge; w->event=w->thread=-1; w->initialized=1;
    w->last_result=VAU_BUSY;
    atomic_init(&w->stopping,0); atomic_init(&w->exited,0); vau_ui_job_init(&w->job);
    int rc=sceKernelCreateEventFlag("VauNoticeWake",0,0,NULL);
    if (rc<0) { w->error=rc; return rc; }
    w->event=rc;
    rc=sceKernelCreateThread("VauNotice",run,0x10000100,0x2000,0,0,NULL);
    if (rc>=0) {
        w->thread=rc;
        struct vau_notification_worker *argument=w;
        rc=sceKernelStartThread(w->thread,sizeof(argument),&argument);
        if (rc>=0) { w->started=1; return VAU_OK; }
    }
    w->error=rc;
    (void)vau_notification_worker_close(w);
    return rc;
}
int vau_notification_worker_poll(struct vau_notification_worker *w,uint64_t now)
{
    if (!w || !w->initialized) return VAU_INVALID;
    int exited=atomic_load_explicit(&w->exited,memory_order_acquire);
    if (w->pending_handle && (exited || !live(w,w->pending_handle,now))) {
        (void)vau_ui_job_cancel(&w->job);
        /* After exit publication no native delivery can access this job again.
         * Complete cancellation acknowledgment so its storage is reclaimable. */
        if (exited) vau_ui_job_dispatch(&w->job);
    }
    int result;
    if (vau_ui_job_result(&w->job,&result)==VAU_OK) {
        w->last_result=result;
        if(result>=0 && w->last_slot<VAU_AUTH_SLOTS)w->announced[w->last_slot]=w->pending_handle;
        if(w->observer)w->observer(result,0);
        w->pending_handle=0;
        (void)vau_ui_job_reset(&w->job);
        if (exited && w->exit_result<0) { w->last_result=w->exit_result; return w->exit_result; }
        return VAU_OK;
    }
    return exited && w->exit_result<0 ? w->exit_result : VAU_OK;
}
int vau_notification_worker_queue(struct vau_notification_worker *w,uint64_t handle,
    const char *name,size_t length,uint64_t now)
{
    if (!w || !w->initialized || !w->started || atomic_load_explicit(&w->exited,memory_order_acquire) || atomic_load_explicit(&w->stopping,memory_order_acquire)) return VAU_DENIED;
    int rc=vau_service_poll(w->service);
    if (rc<0 || !live(w,handle,now)) return VAU_DENIED;
    struct vau_notification packet;
    rc=vau_notification_using(&packet,name,length);
    if (rc<0) return rc;
    unsigned slot=0;
    while (slot<VAU_AUTH_SLOTS && w->service->auth.entries[slot].handle!=handle) ++slot;
    if (slot==VAU_AUTH_SLOTS) return VAU_DENIED;
    if (w->announced[slot]==handle) return VAU_OK;
    (void)vau_notification_worker_poll(w,now);
    if (atomic_load_explicit(&w->job.state,memory_order_acquire)!=VAU_UI_IDLE) return VAU_BUSY;
    memcpy(w->name,name,length); w->name_length=length;
    w->kernel_generation=w->service->stop.generation; w->queued_us=now;
    w->expires_us=w->service->auth.entries[slot].expires_us;
    rc=vau_ui_job_prepare(&w->job,deliver,w);
    if (rc<0) return rc;
    w->pending_handle=handle;w->last_slot=slot;
    if(w->observer)w->observer(VAU_BUSY,1);
    rc=sceKernelSetEventFlag(w->event,1);
    if (rc<0) { w->error=rc; (void)vau_ui_job_cancel(&w->job); }
    return rc;
}

void vau_notification_worker_activity(void *context,uint64_t handle,const char *name,uint64_t now)
{
    struct vau_notification_worker *w=context;
    if(!w || !name)return;
    unsigned slot=0;while(slot<VAU_AUTH_SLOTS && w->service->auth.entries[slot].handle!=handle)++slot;
    if(slot==VAU_AUTH_SLOTS)return;
    uint64_t last=w->activity_us[slot];
    if(last && now>=last && now-last>=UINT64_C(60000000))w->announced[slot]=0;
    /* Successful delivery is deduplicated, failed delivery gets another
     * opportunity on real activity at most once per five seconds. */
    if(w->announced[slot]!=handle && (!last || now<last || now-last>=UINT64_C(5000000))) {
        (void)vau_notification_worker_queue(w,handle,name,strlen(name),now);
        w->activity_us[slot]=now;
    } else if(w->announced[slot]==handle)w->activity_us[slot]=now;
}
