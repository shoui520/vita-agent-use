/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_PAIRING_WORKER_H
#define VAU_PAIRING_WORKER_H
#include "pairing_activation.h"
#include "ui_vita.h"
enum vau_pairing_worker_state { VAU_PAIR_WORK_IDLE,VAU_PAIR_WORK_PENDING,VAU_PAIR_WORK_DONE };
struct vau_pairing_worker {
    struct vau_ui_job job;
    struct vau_pairing_ui ui; /* Shell UI thread only, including callbacks. */
    struct vau_service *service;
    struct vau_notification_worker *notifications;
    const struct vau_native_api *api;
    struct vau_pairing_binding binding;
    struct vau_pairing_grant grant;
    atomic_uint cancelled;
    char name[VAU_AGENT_NAME_BYTES];
    size_t name_length;
    uint64_t last_us,deadline_us;
    enum vau_pairing_worker_state state;
    int begin_job,ui_finished,result;
};
/* Fresh resident storage. All worker functions are serialized with the service.
 * Only posted jobs/native callbacks touch ui. api->clock/context must be safe to
 * read concurrently on the Shell UI thread (the native clock is). */
void vau_pairing_worker_init(struct vau_pairing_worker *worker,struct vau_service *service,
    const struct vau_native_api *api,struct vau_notification_worker *notifications);
/* Pairing TLS must be ready and current must be its immutable peer binding.
 * Start only while service authorization is stopped and stop monitor healthy.
 * Runtime checks shared-dialog coexistence before begin; PAF stays resident. */
int vau_pairing_worker_begin(struct vau_pairing_worker *worker,const struct vau_pairing_binding *current,
    const char *name,size_t length,uint64_t now_us);
/* Call <=16ms apart while pending, with NULL current on disconnect. Collects
 * native OK/Cancel and activates once. BUSY retains UI/job ownership, even after
 * cancellation/deadline; keep polling until DONE, never free/unload on timeout.
 * On success grant is worker-owned; runtime persists trust/delivers token next. */
int vau_pairing_worker_poll(struct vau_pairing_worker *worker,const struct vau_pairing_binding *current,uint64_t now_us);
/* Only after DONE and after consuming grant; wipes the local token for reuse. */
int vau_pairing_worker_reset(struct vau_pairing_worker *worker);
void vau_pairing_worker_cancel(struct vau_pairing_worker *worker);
#endif
