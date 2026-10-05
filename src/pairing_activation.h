/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_PAIRING_ACTIVATION_H
#define VAU_PAIRING_ACTIVATION_H
#include "pairing_ui.h"
#include "notification_worker.h"
#define VAU_PAIRING_GRANT_US UINT64_C(3600000000)
struct vau_pairing_grant {
    uint64_t handle;
    char token[VAU_TOKEN_HEX_BYTES+1];
    int notification_result;
};
/* Trusted serialized service worker only, immediately after collecting the
 * completed native UI job. decision is the native OK/Cancel result; approval
 * is its immutable binding, current is the still-connected TLS peer binding.
 * Caller consumes the UI decision once. No HTTP route exposes this function.
 * Existing UI input inhibition stays in place until the current OK is checked.
 * Returns a local grant; certificate persistence and protected token delivery
 * are separate runtime steps. Do not log the token or promote pairing TLS to
 * command TLS. Notification errors are reported independently of authorization. */
int vau_vita_pairing_activate(struct vau_service *service,int decision,
    const struct vau_pairing_binding *approval,const struct vau_pairing_binding *current,
    struct vau_notification_worker *notifications,const char *name,size_t length,
    uint64_t now_us,struct vau_pairing_grant *out);
/* The owner calls only after strict TLS verified the locally saved peer.
 * Refuses any kernel stop generation since boot: reconnect cannot undo
 * PS+SELECT. Saved-peer renewal is silent and permits temporary screen-off
 * sampling unavailability; real commands restore full readiness before effects. */
int vau_vita_session_activate(struct vau_service *service,
    const struct vau_pairing_binding *binding,const unsigned char saved_sha256[32],
    struct vau_notification_worker *notifications,const char *name,size_t length,
    uint64_t now_us,struct vau_pairing_grant *out);
#endif
