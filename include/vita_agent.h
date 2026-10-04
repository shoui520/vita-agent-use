/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VITA_AGENT_H
#define VITA_AGENT_H
#include <stdint.h>

#define VAU_ABI 1u
#define VAU_MAX_EVENTS 1024u
#define VAU_MAX_DURATION_US 3600000000u
#define VAU_LEASE_US 5000000u
#define VAU_MAX_REPEATS 1000000u
/* Digital face/dpad/start/select/shoulder controls only. System buttons need
 * their own operations rather than unrestricted controller bit injection. */
#define VAU_BUTTON_MASK 0x0000f3f9u

enum vau_error {
    VAU_OK = 0, VAU_INVALID = -1, VAU_BUSY = -2, VAU_EXPIRED = -3,
    VAU_DENIED = -4, VAU_STALE = -5, VAU_UNSUPPORTED = -6,
    VAU_DEVICE_ERROR = -7, VAU_LATE = -8, VAU_RECOVERY_REQUIRED = -9
};
enum vau_run_state {
    VAU_IDLE, VAU_QUEUED, VAU_RUNNING, VAU_FINISHED,
    VAU_CANCELLED, VAU_LEASE_EXPIRED, VAU_FAILED
};
typedef struct VauPad {
    uint32_t buttons;
    uint8_t lx, ly, rx, ry;
} VauPad;
typedef struct VauEvent {
    uint32_t at_us;
    VauPad pad;
} VauEvent;
/* Full panel state at the corresponding controller event's timestamp.
 * enabled bits: front=1, rear=2. An enabled panel with count zero releases
 * its contacts; a disabled panel keeps physical input. Coordinates are native
 * touch units from touch.panels, not screenshot pixels. */
typedef struct vau_touch_contact { uint8_t id,force; int16_t x,y; uint16_t reserved; } VauTouchContact;
typedef struct VauTouchState {
    uint8_t enabled,count[2],reserved;
    VauTouchContact contacts[2][6];
} VauTouchState;
typedef struct VauSequence {
    uint32_t size, abi;
    uint64_t request_id;
    uint64_t start_us;
    uint32_t count, duration_us, repeats, max_lateness_us;
} VauSequence;
typedef struct VauStatus {
    uint32_t size, abi, state;
    int32_t error;
    uint64_t request_id, now_us, started_us, last_applied_us, lease_until_us;
    uint32_t iteration, next_event, applied_events, max_lateness_us;
    VauPad pad;
} VauStatus;
typedef struct VauStopStatus {
    uint32_t size, abi;
    uint64_t generation;
    uint32_t stopped, ready, chord_held;
    int32_t observation_error;
} VauStopStatus;

/* Read-only monitor evidence; timestamps are native, process-relative values.
 * reason: 0 healthy, 1 native call, 2 count, 3 mask, 4/5 reserved (legacy timestamp checks),
 * 6 host clock regression, 7 timestamp not advancing. */
typedef struct VauInputObservation {
    uint32_t size, abi;
    uint64_t stamp, previous_stamp, observed_us, changed_us;
    int32_t result, error;
    uint32_t mask, buttons, reason, sampled;
} VauInputObservation;
int vauInputGetObservation(VauInputObservation *observation);

/* applied_events/last_applied_us report acceptance by the native emulation
 * API, not proof that a game sampled the input or performed an action.
 * pad is the last successfully submitted state, not a hardware observation. */

/* Native bridge callable by the SceShell service. All structs use fixed-width
 * fields; the kernel copies and validates user memory before publication.
 * Poll/GetStatus do not renew the lease. A controller explicitly heartbeats. */
int vauInputAcquire(void);
/* Optional game/process binding. Requires that PID to be the native controller
 * routing target. An observed change invalidates the lease and sequence; no
 * automatic resume. Sampling is not an atomic guarantee against routing races. */
int vauInputAcquireForProcess(int32_t process_id);
int vauInputHeartbeat(void);
int vauInputSubmit(const VauSequence *sequence, const VauEvent *events);
/* Same sequence timing/repeats/lease, one touch state per event. Ordinary input
 * remains unbound; a macro's process binding also applies to its touch states.
 * Shell copies are validated before deferred hooking. */
int vauInputSubmitTouch(const VauSequence *sequence,const VauEvent *events,const VauTouchState *touch);
/* Process-bound macro continuation; zero start derives the prior segment end.
 * Optional touch contains one state per event, same limits as SubmitTouch. */
int vauInputEnqueue(const VauSequence *sequence,const VauEvent *events,const VauTouchState *touch);
int vauInputCancel(void);
int vauInputRelease(void);
int vauInputGetStatus(VauStatus *status);
/* Trusted Shell approval UI only; never expose as an agent command. Enable
 * before showing a prompt and require success. Disable after the prompt has
 * closed; a fresh lease is required. Covers this service's emulation only. */
int vauInputSetApprovalGate(int enabled);
/* Trusted Shell coordination. Observe before granting/dispatching control and
 * revoke sessions on generation change. Rearm only after new local approval;
 * it never grants a lease or restores a previous session. The first authorized
 * GetStopStatus starts native monitoring asynchronously. Until a fresh sample
 * arrives, ready is false and acquisition/rearm remain denied. Monitoring then
 * stays active until reboot, including after disconnection or emergency stop. */
int vauInputGetStopStatus(VauStopStatus *status);
int vauInputRearm(uint64_t generation);

typedef struct VauFrameInfo {
    uint32_t size,abi,width,height,pitch,pixel_format,bytes,head;
    int32_t process_id;
    uint32_t vblank_count;
    uint64_t started_us,finished_us;
} VauFrameInfo;
/* Shell-only snapshot of the configured primary display, preferring Shell index 1. Output is
 * A8B8G8R8 with pitch aligned to 64 pixels; metadata may describe an observed source on failure, with bytes=0. Discard pixels
 * on error, including VAU_STALE if the display changed during the copy. This
 * detects descriptor changes, not all concurrent GPU writes/tearing. */
int vauScreenCapture(void *pixels,uint32_t capacity,VauFrameInfo *info);

#endif
