/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_INPUT_OWNER_H
#define VAU_INPUT_OWNER_H
#include "auth.h"
struct vau_input_bridge {
    void *context;
    uint64_t (*clock)(void *context);
    int (*acquire)(void *context);
    int (*heartbeat)(void *context);
    int (*submit)(void *context,const VauSequence *sequence,const VauEvent *events);
    int (*cancel)(void *context);
    int (*release)(void *context);
    int (*status)(void *context,VauStatus *status);
    int (*acquire_process)(void *context,int32_t process);
    int (*submit_touch)(void *context,const VauSequence *sequence,const VauEvent *events,const VauTouchState *touch);
    int (*enqueue)(void *context,const VauSequence *sequence,const VauEvent *events,const VauTouchState *touch);
};
struct vau_input_owner {
    struct vau_input_bridge bridge;
    uint64_t handle,lease_until,last_us,next_sequence;
    int initialized,cleanup;
    int32_t process;
};
extern const struct vau_input_bridge vau_vita_input_bridge;
int vau_input_owner_enqueue(struct vau_input_owner *,const struct vau_auth *,uint64_t,
    const VauSequence *,const VauEvent *,const VauTouchState *,uint64_t *);
/* Serialized with auth and service. Handles come from the local grant registry,
 * never from a remotely supplied ownership claim. Poll while idle, not just on
 * commands, to release revoked/expired owners. Poll never renews a lease. */
int vau_input_owner_init(struct vau_input_owner *input,const struct vau_input_bridge *bridge);
int vau_input_owner_poll(struct vau_input_owner *input,const struct vau_auth *auth);
int vau_input_owner_acquire(struct vau_input_owner *input,const struct vau_auth *auth,uint64_t handle);
int vau_input_owner_acquire_process(struct vau_input_owner *input,const struct vau_auth *auth,uint64_t handle,int32_t process);
int vau_input_owner_heartbeat(struct vau_input_owner *input,const struct vau_auth *auth,uint64_t handle);
int vau_input_owner_submit(struct vau_input_owner *input,const struct vau_auth *auth,uint64_t handle,
    const VauSequence *sequence,const VauEvent *events,uint64_t *execution_id);
int vau_input_owner_submit_touch(struct vau_input_owner *input,const struct vau_auth *auth,uint64_t handle,
    const VauSequence *sequence,const VauEvent *events,const VauTouchState *touch,uint64_t *execution_id);
int vau_input_owner_cancel(struct vau_input_owner *input,const struct vau_auth *auth,uint64_t handle);
int vau_input_owner_release(struct vau_input_owner *input,const struct vau_auth *auth,uint64_t handle);
int vau_input_owner_status(struct vau_input_owner *input,const struct vau_auth *auth,uint64_t handle,VauStatus *status);
#endif
