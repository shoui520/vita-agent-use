/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "pairing_activation.h"
#include <string.h>
static int same_binding(const struct vau_pairing_binding *a,const struct vau_pairing_binding *b)
{
    return a && b && a->connection && a->connection==b->connection &&
        a->local_stop_generation==b->local_stop_generation &&
        a->kernel_stop_generation==b->kernel_stop_generation &&
        !memcmp(a->certificate_sha256,b->certificate_sha256,sizeof(a->certificate_sha256));
}
int vau_vita_pairing_activate(struct vau_service *s,int decision,
    const struct vau_pairing_binding *approval,const struct vau_pairing_binding *current,
    struct vau_notification_worker *notifications,const char *name,size_t length,
    uint64_t now,struct vau_pairing_grant *out)
{
    if (!out) return VAU_INVALID;
    memset(out,0,sizeof(*out));
    out->notification_result=VAU_UNSUPPORTED;
    if (!s || decision!=VAU_OK) return VAU_DENIED;
    if (!same_binding(approval,current)) return VAU_STALE;
    uint16_t label[VAU_AGENT_NAME_BYTES]; size_t units;
    int rc=vau_agent_name_utf16(label,&units,name,length);
    if (rc<0 || now>UINT64_MAX-VAU_PAIRING_GRANT_US) return rc<0 ? rc : VAU_INVALID;
    if (notifications && (notifications->service!=s || !notifications->initialized ||
        !notifications->started || atomic_load_explicit(&notifications->stopping,memory_order_acquire) ||
        atomic_load_explicit(&notifications->exited,memory_order_acquire))) return VAU_INVALID;
    (void)vau_service_poll(s);
    if (!s->valid || !s->stop.ready || s->stop.chord_held || s->stop.observation_error) return VAU_DENIED;
    if (s->input.initialized && s->input.cleanup) return VAU_BUSY;
    if (approval->local_stop_generation!=s->auth.stop_generation ||
        approval->kernel_stop_generation!=s->stop.generation) return VAU_STALE;
    /* Native OK is the consent decision. No extra controller sampling. */
    rc=vauInputSetApprovalGate(0);
    if (rc<0) goto failed;
    if (s->auth.stopped) {
        rc=vau_service_rearm(s,approval->local_stop_generation,approval->kernel_stop_generation);
        if (rc<0) goto failed;
    }
    rc=vau_service_grant(s,VAU_RIGHT_OBSERVE|VAU_RIGHT_CONTROL,now,
        VAU_PAIRING_GRANT_US,vau_vita_entropy,NULL,&out->handle,out->token);
    if (rc<0) goto failed;
    struct vau_session *session=vau_auth_lookup(&s->auth,out->token,64,now);
    if(!session){rc=VAU_DENIED;goto failed;}
    static const char hex[]="0123456789abcdef";
    for(unsigned i=0;i<32;++i) {
        session->subject[i*2]=hex[approval->certificate_sha256[i]>>4];
        session->subject[i*2+1]=hex[approval->certificate_sha256[i]&15];
    }
    session->subject[64]=0;
    memcpy(session->agent_name,name,length);session->agent_name[length]=0;
    rc=vau_service_poll(s);
    if (rc<0 || approval->local_stop_generation!=s->auth.stop_generation ||
        approval->kernel_stop_generation!=s->stop.generation) { rc=VAU_STALE; goto failed; }
    if (notifications)
        out->notification_result=vau_notification_worker_queue(notifications,out->handle,name,length,now);
    return VAU_OK;
failed:
    /* Failed activation must not leave rearmed control without a delivered grant.
     * A new native approval is required; no token or input lease is restored. */
    if (!s->auth.stopped) vau_auth_stop(&s->auth);
    (void)vauInputSetApprovalGate(1);
    (void)vau_service_poll(s);
    memset(out,0,sizeof(*out)); out->notification_result=VAU_UNSUPPORTED;
    return rc;
}

int vau_vita_session_activate(struct vau_service *s,
    const struct vau_pairing_binding *binding,const unsigned char saved_sha256[32],
    struct vau_notification_worker *notifications,const char *name,size_t length,
    uint64_t now,struct vau_pairing_grant *out)
{
    if (!out) return VAU_INVALID;
    memset(out,0,sizeof(*out)); out->notification_result=VAU_UNSUPPORTED;
    if (!s || !binding || !saved_sha256 ||
        memcmp(binding->certificate_sha256,saved_sha256,32)) return VAU_DENIED;
    (void)vau_service_poll(s);
    /* Persistent consent permits normal reconnect, never clearing a physical
     * stop or monitor fault. A reboot starts a new kernel stop generation. */
    if (!s->valid || !s->stop.ready || s->stop.stopped || s->stop.generation ||
        binding->kernel_stop_generation || s->stop.chord_held || s->stop.observation_error)
        return VAU_DENIED;
    return vau_vita_pairing_activate(s,VAU_OK,binding,binding,notifications,name,length,now,out);
}
