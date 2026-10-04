/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "acl_approval.h"
#include <string.h>
static int step(void *context)
{
    struct vau_acl_approval *w=context;
    uint64_t now=w->api->clock(w->api->context);
    if(now>=w->deadline)atomic_store_explicit(&w->cancelled,1,memory_order_release);
    if(w->begin_job) {
        vau_pairing_ui_init(&w->ui);
        if(atomic_load_explicit(&w->cancelled,memory_order_acquire)){w->ui_finished=1;return VAU_DENIED;}
        int rc=vau_pairing_ui_begin_prompt(&w->ui,&w->binding,&w->prompt,now);
        if(w->ui.state==VAU_PAIR_UI_IDLE){w->ui_finished=1;return rc;}
    }
    if(atomic_load_explicit(&w->cancelled,memory_order_acquire))vau_pairing_ui_cancel(&w->ui);
    int rc=vau_pairing_ui_poll(&w->ui,&w->binding,now);
    w->ui_finished=w->ui.state==VAU_PAIR_UI_DONE;
    return w->ui_finished ? rc:VAU_BUSY;
}
static int post(struct vau_acl_approval *w)
{
    int rc=vau_ui_job_prepare(&w->job,step,w);
    if(rc<0)return rc;
    rc=vau_ui_post(&w->job);
    if(rc<0 && !w->job.posted)(void)vau_ui_job_rejected(&w->job);
    return rc;
}
void vau_acl_approval_init(struct vau_acl_approval *w,struct vau_service *s,const struct vau_native_api *api)
{
    memset(w,0,sizeof(*w));w->service=s;w->api=api;
    atomic_init(&w->cancelled,0);vau_ui_job_init(&w->job);
}
void vau_acl_approval_cancel(struct vau_acl_approval *w)
{if(w && w->active)atomic_store_explicit(&w->cancelled,1,memory_order_release);}
int vau_acl_approval_begin(struct vau_acl_approval *w,uint64_t handle,const char *subject,const struct vau_pairing_prompt *prompt)
{
    if(!w || !handle || !subject || strlen(subject)!=64 || !prompt)return VAU_INVALID;
    if(w->active || w->service->approval_pending)return VAU_BUSY;
    if(vau_service_poll(w->service)<0)return VAU_DENIED;
    uint64_t now=w->api->clock(w->api->context);
    if(now>UINT64_MAX-VAU_PAIRING_UI_TIMEOUT_US)return VAU_INVALID;
    if(!w->api->system_ui_overlaid || w->api->system_ui_overlaid(w->api->context)!=0)return VAU_BUSY;
    /* The kernel gate clears scheduled pad/touch input before opening UI. */
    w->active=1;w->handle=handle;w->result=VAU_BUSY;
    w->service->approval_pending=1;
    int rc=vauInputSetApprovalGate(1);
    if(rc<0){w->result=rc;return VAU_OK;}
    if(w->service->input.initialized && w->service->input.handle) {
        rc=vau_input_owner_release(&w->service->input,&w->service->auth,w->service->input.handle);
        if(rc<0){w->result=rc;return VAU_OK;} /* No dialog until input release succeeds. */
    }
    memset(&w->binding,0,sizeof(w->binding));w->binding.connection=handle;
    w->binding.local_stop_generation=w->service->auth.stop_generation;
    w->binding.kernel_stop_generation=w->service->stop.generation;
    static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<32;++i) {
        const char *a=strchr(hex,subject[i*2]),*b=strchr(hex,subject[i*2+1]);
        if(!a || !b){w->result=VAU_INVALID;return VAU_OK;}
        w->binding.certificate_sha256[i]=(unsigned char)(((a-hex)<<4)|(b-hex));
    }
    w->prompt=*prompt;w->handle=handle;w->deadline=now+VAU_PAIRING_UI_TIMEOUT_US;
    w->active=1;w->begin_job=1;w->ui_finished=0;w->result=VAU_BUSY;
    atomic_store_explicit(&w->cancelled,0,memory_order_release);
    rc=post(w);if(rc<0)vau_acl_approval_cancel(w);
    return VAU_OK; /* The queued request has a terminal status even if posting failed. */
}
int vau_acl_approval_poll(struct vau_acl_approval *w)
{
    if(!w || !w->active)return VAU_INVALID;
    if(w->result!=VAU_BUSY)return w->result;
    struct vau_service *s=w->service;uint64_t now=w->api->clock(w->api->context);
    int live=0;
    for(unsigned i=0;i<VAU_AUTH_SLOTS;++i)
        if(s->auth.entries[i].handle==w->handle && now<s->auth.entries[i].expires_us)live=1;
    if(vau_service_poll(s)<0 || !live || now>=w->deadline ||
        s->auth.stop_generation!=w->binding.local_stop_generation || s->stop.generation!=w->binding.kernel_stop_generation)
        vau_acl_approval_cancel(w);
    int decision;if(vau_ui_job_result(&w->job,&decision)!=VAU_OK)return VAU_BUSY;
    unsigned posted=w->job.posted;(void)vau_ui_job_reset(&w->job);
    if(w->ui_finished || (w->begin_job && !posted)) {
        w->result=atomic_load_explicit(&w->cancelled,memory_order_acquire) ? VAU_DENIED:decision;
        return w->result;
    }
    w->begin_job=0;if(post(w)<0)vau_acl_approval_cancel(w);
    return VAU_BUSY;
}
int vau_acl_approval_finish(struct vau_acl_approval *w)
{
    if(!w || !w->active || w->result==VAU_BUSY)return VAU_BUSY;
    int rc=vauInputSetApprovalGate(0);if(rc<0)return rc;
    w->service->approval_pending=0;w->active=0;return VAU_OK;
}
