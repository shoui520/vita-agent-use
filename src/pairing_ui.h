/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_PAIRING_UI_H
#define VAU_PAIRING_UI_H
#include "dialog_vita.h"
#define VAU_PAIRING_UI_TIMEOUT_US UINT64_C(60000000)
struct vau_pairing_binding {
    /* Connection IDs must be local, unique, nonzero, and never reused. */
    uint64_t connection,local_stop_generation,kernel_stop_generation;
    unsigned char certificate_sha256[32];
    unsigned replace_peer; /* Local UI intent; never supplied by the peer. */
};
enum vau_pairing_ui_state { VAU_PAIR_UI_IDLE, VAU_PAIR_UI_ACTIVE, VAU_PAIR_UI_DONE };
struct vau_pairing_ui {
    struct vau_pairing_binding binding;
    struct vau_pairing_prompt prompt;
    uint64_t last_us,deadline_us;
    int32_t dialog_id,event_id,event_result;
    enum vau_pairing_ui_state state;
    unsigned opening,released,result_seen,lifecycle_seen,closing,cancelled;
    int open_status;
};
/* All functions and callbacks run on the Shell UI thread. A worker must use
 * the UI job queue, never access this object concurrently. Storage and code
 * remain resident until both native callback objects have been released.
 * The caller must inhibit input and check UI coexistence before begin. */
void vau_pairing_ui_init(struct vau_pairing_ui *ui);
int vau_pairing_ui_begin(struct vau_pairing_ui *ui,const struct vau_pairing_binding *binding,
    const char *name,size_t name_length,uint64_t now_us);
int vau_pairing_ui_begin_prompt(struct vau_pairing_ui *,const struct vau_pairing_binding *,
    const struct vau_pairing_prompt *,uint64_t now_us);
/* NULL current means disconnected. Changes to either stop generation or peer
 * identity cancel this transaction. Call while waiting, including on timeout.
 * VAU_OK is the native OK decision. The worker validates current service state
 * and the immutable binding before storing trust or issuing a grant. */
int vau_pairing_ui_poll(struct vau_pairing_ui *ui,const struct vau_pairing_binding *current,
    uint64_t now_us);
void vau_pairing_ui_cancel(struct vau_pairing_ui *ui);
/* Only after DONE. Must also have acknowledged any UI jobs using this object. */
int vau_pairing_ui_reset(struct vau_pairing_ui *ui);
#endif
