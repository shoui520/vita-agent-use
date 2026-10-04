/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "timeline.h"
#include "vau_modules.h"
#include "vau_events.h"
#include "vau_performance.h"
#include "stop_monitor.h"
#include "capture_kernel.h"
#include "touch_kernel.h"
#include <psp2kern/ctrl.h>
#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/sysroot.h>
#include <psp2kern/kernel/threadmgr.h>
#include <string.h>

/* No patches, firmware lookups, filesystem access or networking during boot.
 * Slot 3 is reserved for this runtime. ds4vita's examined revision uses slot 0.
 * The service must negotiate conflicts before enabling other input plugins. */
#define INPUT_SLOT 3u
#define REFRESH_US 8000u
static struct vau_timeline timeline;
static VauEvent staging[VAU_MAX_EVENTS];
static VauTouchState touch_staging[VAU_MAX_EVENTS];
static struct vau_touch_panel touch_panels[2];
static uint64_t touch_changed;
static int touch_published;
static SceUID guard=-1, wake=-1, worker=-1;
static uint64_t refreshed;
static int emulating;
static struct vau_stop_monitor stop_monitor;
static uint64_t stop_polled;
static int stop_polled_once;
/* Protected by guard. Once Shell requests monitoring it stays active until
 * reboot; no caller can turn the emergency stop off during a session. */
static int monitor_enabled;
extern int vauCtrlGetRoutingProcess(int32_t *process);
_Static_assert(sizeof(VauStopStatus)==32,"stop status ABI");
_Static_assert(sizeof(VauInputObservation)==64,"input observation ABI");
_Static_assert(VAU_STOP_CHORD==(SCE_CTRL_PSBUTTON|SCE_CTRL_SELECT),"native stop buttons");

static uint64_t now_us(void) { return (uint64_t)ksceKernelGetSystemTimeWide(); }
static int authorized(void)
{
    SceUID shell=ksceKernelSysrootGetShellPid();
    return shell>0 && ksceKernelGetProcessId()==shell;
}
int vauScreenCapture(void *pixels,uint32_t capacity,VauFrameInfo *user_info)
{
    uint32_t state;
    int rc;
    VauFrameInfo info={0};
    ENTER_SYSCALL(state);
    /* Screen copy runs on the caller's thread without holding the input guard. */
    rc=authorized() ? vau_capture_kernel(pixels,capacity,&info) : VAU_DENIED;
    if (info.size==sizeof(info) && info.abi==VAU_ABI) {
        int copied=ksceKernelCopyToUser(user_info,&info,sizeof(info));
        if (copied<0) rc=copied;
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauPluginState(int32_t pid,const char user_path[256],VauPluginState *user_state)
{
    uint32_t state;int rc;char path[256];VauPluginState observed={0};
    ENTER_SYSCALL(state);
    rc=authorized() ? ksceKernelCopyFromUser(path,user_path,sizeof(path)) : VAU_DENIED;
    if(rc>=0)rc=vau_modules_kernel_state(pid,path,&observed);
    if(rc>=0)rc=ksceKernelCopyToUser(user_state,&observed,sizeof(observed));
    EXIT_SYSCALL(state);return rc;
}
int vauPerformanceRead(uint32_t enabled,VauPerformanceRaw *user_out)
{
    uint32_t state;int rc;VauPerformanceRaw out={0};
    ENTER_SYSCALL(state);
    rc=authorized() ? vau_performance_kernel(enabled,&out) : VAU_DENIED;
    if(rc>=0)rc=ksceKernelCopyToUser(user_out,&out,sizeof(out));
    EXIT_SYSCALL(state);return rc;
}
int vauDumpEvents(uint32_t operation,uint32_t after,VauDumpPage *user_out)
{
    uint32_t state;int rc;VauDumpPage out={0};
    ENTER_SYSCALL(state);
    rc=authorized() ? vau_dump_events_kernel(operation,after,&out) : VAU_DENIED;
    if(rc>=0)rc=ksceKernelCopyToUser(user_out,&out,sizeof(out));
    EXIT_SYSCALL(state);return rc;
}
static void clear_touch(void)
{
    if (touch_published) { vau_touch_kernel_clear(); touch_published=0; }
}
static int apply_pad(void *context, const VauPad *pad)
{
    (void)context;
    int buttons, analog;
    /* Short native sampling lifetime provides a second release mechanism if
     * the worker is delayed. Worker refreshes only while a lease is active. */
    if (pad) {
        buttons=ksceCtrlSetButtonEmulation(0,INPUT_SLOT,pad->buttons,pad->buttons,4);
        analog=ksceCtrlSetAnalogEmulation(0,INPUT_SLOT,pad->lx,pad->ly,pad->rx,pad->ry,
                                        pad->lx,pad->ly,pad->rx,pad->ry,4);
        emulating=1;
        refreshed=now_us();
        if (buttons>=0 && analog>=0) {
            const VauTouchState *touch=vau_timeline_current_touch(&timeline);
            if (touch && touch->enabled) {
                if (pad!=&timeline.status.pad) touch_changed=refreshed;
                struct vau_touch_pose pose;
                int rc=vau_timeline_touch_pose(&timeline,refreshed,touch_changed,&pose);
                if (rc>=0) rc=vau_touch_kernel_publish(&pose,touch_panels);
                if (rc<0) return rc;
                touch_published=1;
            } else clear_touch();
        }
    } else {
        clear_touch();
        if (!emulating) return 0;
        buttons=ksceCtrlSetButtonEmulation(0,INPUT_SLOT,0,0,0);
        analog=ksceCtrlSetAnalogEmulation(0,INPUT_SLOT,128,128,128,128,128,128,128,128,0);
        if (buttons>=0 && analog>=0) emulating=0;
    }
    return buttons<0 ? buttons : analog;
}
static void poll_stop(uint64_t now)
{
    if (stop_polled_once && now>=stop_polled && now-stop_polled<VAU_STOP_POLL_US) return;
    stop_polled=now;
    stop_polled_once=1;
    SceCtrlData sample={0};
    uint32_t mask=0;
    int rc=ksceCtrlGetMaskForAll(&mask);
    if (rc>=0) {
        rc=ksceCtrlPeekBufferPositive(0,&sample,1);
        if (rc<0) rc=ksceCtrlPeekBufferPositive(1,&sample,1);
    }
    if (vau_stop_observe(&stop_monitor,rc,mask,sample.buttons,sample.timeStamp,now))
        vau_timeline_stop(&timeline,now,apply_pad,NULL);
    else if (stop_monitor.error && timeline.leased) {
        /* A failed observation cancels automation, but is not a user stop.
         * Recovery requires a new lease; no old sequence resumes. */
        int release=vau_timeline_release(&timeline,now,apply_pad,NULL);
        timeline.status.state=VAU_FAILED;
        timeline.status.error=release<0 ? release : stop_monitor.error;
    }
}
static int check_process(uint64_t now)
{
    if (!timeline.expected_process) return VAU_OK;
    int32_t process=-1;
    int rc=vauCtrlGetRoutingProcess(&process);
    return vau_timeline_check_process(&timeline,process,rc,now,apply_pad,NULL);
}
static int input_worker(SceSize argc, void *args)
{
    (void)argc; (void)args;
    for (;;) {
        uint32_t wait=100000;
        if (ksceKernelLockMutex(guard,1,NULL)>=0) {
            if (!monitor_enabled) {
                ksceKernelUnlockMutex(guard,1);
                /* Boot creates only our synchronization objects and thread.
                 * Do not sample Ctrl or wake periodically before Shell asks. */
                ksceKernelWaitEventFlag(wake,1,SCE_EVENT_WAITOR|SCE_EVENT_WAITCLEAR_PAT,NULL,NULL);
                continue;
            }
            uint64_t now=now_us();
            poll_stop(now);
            (void)check_process(now);
            vau_timeline_tick(&timeline,now,apply_pad,NULL);
            if (emulating && timeline.status.state==VAU_RUNNING && now>=refreshed && now-refreshed>=REFRESH_US) {
                int rc=apply_pad(NULL,&timeline.status.pad);
                if (rc<0) {
                    vau_timeline_cancel(&timeline,now,apply_pad,NULL);
                    timeline.status.state=VAU_FAILED;
                    timeline.status.error=rc;
                }
            } else if (emulating && timeline.status.state!=VAU_RUNNING) {
                apply_pad(NULL,NULL);
            }
            wait=vau_timeline_wait_us(&timeline,now_us());
            if (emulating && wait>REFRESH_US) wait=REFRESH_US;
            if (wait>VAU_STOP_POLL_US) wait=VAU_STOP_POLL_US;
            ksceKernelUnlockMutex(guard,1);
        }
        ksceKernelWaitEventFlag(wake,1,SCE_EVENT_WAITOR|SCE_EVENT_WAITCLEAR_PAT,NULL,&wait);
    }
    return 0;
}
static int enter(void)
{
    if (!authorized()) return VAU_DENIED;
    return ksceKernelLockMutex(guard,1,NULL);
}
static int leave(int rc)
{
    ksceKernelUnlockMutex(guard,1);
    ksceKernelSetEventFlag(wake,1);
    return rc;
}
int vauInputAcquire(void)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        uint64_t now=now_us();
        if (vau_stop_ready(&stop_monitor,now)) {
            (void)check_process(now);
            vau_timeline_tick(&timeline,now,apply_pad,NULL);
            rc=leave(vau_timeline_acquire(&timeline,now));
        } else rc=leave(VAU_DENIED);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputAcquireForProcess(int32_t process)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        uint64_t now=now_us();
        if (process<=0) rc=VAU_INVALID;
        else if (!vau_stop_ready(&stop_monitor,now)) rc=VAU_DENIED;
        else {
            (void)check_process(now);
            vau_timeline_tick(&timeline,now,apply_pad,NULL);
            int32_t observed=-1;
            int read=vauCtrlGetRoutingProcess(&observed);
            rc=vau_timeline_acquire_process(&timeline,process,observed,read,now);
        }
        rc=leave(rc);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputHeartbeat(void)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        uint64_t now=now_us();
        (void)check_process(now);
        rc=leave(vau_stop_ready(&stop_monitor,now) ?
            vau_timeline_heartbeat(&timeline,now) : VAU_DENIED);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputSubmit(const VauSequence *user_sequence, const VauEvent *user_events)
{
    VauSequence sequence;
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        rc=ksceKernelCopyFromUser(&sequence,user_sequence,sizeof(sequence));
        if (rc>=0) {
            if (!sequence.count || sequence.count>VAU_MAX_EVENTS) rc=VAU_INVALID;
            else {
                rc=ksceKernelCopyFromUser(staging,user_events,sequence.count*sizeof(*staging));
                if (rc>=0) {
                    uint64_t now=now_us();
                    (void)check_process(now);
                    rc=vau_stop_ready(&stop_monitor,now) ?
                        vau_timeline_submit(&timeline,&sequence,staging,now) : VAU_DENIED;
                }
            }
        }
        rc=leave(rc);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputSubmitTouch(const VauSequence *user_sequence,const VauEvent *user_events,
    const VauTouchState *user_touch)
{
    VauSequence sequence;
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        uint64_t now=now_us();
        (void)check_process(now);
        vau_timeline_tick(&timeline,now,apply_pad,NULL);
        if (!vau_stop_ready(&stop_monitor,now) || timeline.inhibited || timeline.stopped)
            rc=VAU_DENIED;
        else if (!timeline.leased || now>=timeline.lease_until) rc=VAU_EXPIRED;
        else rc=ksceKernelCopyFromUser(&sequence,user_sequence,sizeof(sequence));
        if (rc>=0) {
            if (!sequence.count || sequence.count>VAU_MAX_EVENTS) rc=VAU_INVALID;
            else {
                rc=ksceKernelCopyFromUser(staging,user_events,sequence.count*sizeof(*staging));
                if (rc>=0) rc=ksceKernelCopyFromUser(touch_staging,user_touch,sequence.count*sizeof(*touch_staging));
                if (rc>=0 && sequence.request_id==timeline.sequence.request_id)
                    rc=vau_timeline_submit_touch(&timeline,&sequence,staging,touch_staging,touch_panels,now_us());
                else if (rc>=0) {
                    struct vau_touch_panel panels[2]={{0}};
                    unsigned enabled=0;
                    for (unsigned i=0;i<sequence.count;i++) enabled|=touch_staging[i].enabled;
                    for (unsigned port=0;port<2 && rc>=0;port++)
                        if (enabled&(1u<<port)) rc=vau_touch_kernel_panel(port,&panels[port]);
                    if (rc>=0) rc=vau_timeline_validate_touch(&timeline,&sequence,staging,touch_staging,panels,now_us());
                    /* No patching for malformed input, expired leases or busy
                     * sequences. Installation precedes committing the queue. */
                    if (rc>=0 && enabled) rc=vau_touch_kernel_enable();
                    if (rc>=0) rc=vau_timeline_submit_touch(&timeline,&sequence,staging,touch_staging,panels,now_us());
                    if (rc>=0) memcpy(touch_panels,panels,sizeof(panels));
                }
            }
        }
        rc=leave(rc);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputEnqueue(const VauSequence *user_sequence,const VauEvent *user_events,
    const VauTouchState *user_touch)
{
    VauSequence sequence;uint32_t state;int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if(rc>=0) {
        uint64_t now=now_us();(void)check_process(now);
        vau_timeline_tick(&timeline,now,apply_pad,NULL);
        if(!vau_stop_ready(&stop_monitor,now) || timeline.inhibited || timeline.stopped || !timeline.expected_process)
            rc=VAU_DENIED;
        else if(!timeline.leased || now>=timeline.lease_until)rc=VAU_EXPIRED;
        else rc=ksceKernelCopyFromUser(&sequence,user_sequence,sizeof(sequence));
        if(rc>=0) {
            if(!sequence.count || sequence.count>VAU_MAX_EVENTS)rc=VAU_INVALID;
            else {
                rc=ksceKernelCopyFromUser(staging,user_events,sequence.count*sizeof(*staging));
                if(rc>=0 && user_touch)rc=ksceKernelCopyFromUser(touch_staging,user_touch,sequence.count*sizeof(*touch_staging));
                struct vau_touch_panel panels[2];memcpy(panels,touch_panels,sizeof(panels));
                unsigned enabled=0;
                if(user_touch && rc>=0) {
                    for(unsigned i=0;i<sequence.count;++i)enabled|=touch_staging[i].enabled;
                    for(unsigned port=0;port<2 && rc>=0;++port)
                        if(enabled&(1u<<port))rc=vau_touch_kernel_panel(port,&panels[port]);
                }
                if(rc>=0)rc=vau_timeline_enqueue(&timeline,&sequence,staging,user_touch ? touch_staging:NULL,panels,now_us(),1);
                if(rc>=0 && enabled)rc=vau_touch_kernel_enable();
                if(rc>=0)rc=vau_timeline_enqueue(&timeline,&sequence,staging,user_touch ? touch_staging:NULL,panels,now_us(),0);
                if(rc>=0 && user_touch)memcpy(touch_panels,panels,sizeof(panels));
            }
        }
        rc=leave(rc);
    }
    EXIT_SYSCALL(state);return rc;
}
int vauInputCancel(void)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) rc=leave(vau_timeline_cancel(&timeline,now_us(),apply_pad,NULL));
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputRelease(void)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) rc=leave(vau_timeline_release(&timeline,now_us(),apply_pad,NULL));
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputGetStatus(VauStatus *user_status)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        timeline.status.now_us=now_us();
        (void)check_process(timeline.status.now_us);
        rc=ksceKernelCopyToUser(user_status,&timeline.status,sizeof(timeline.status));
        ksceKernelUnlockMutex(guard,1);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputSetApprovalGate(int enabled)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) rc=leave(vau_timeline_inhibit(&timeline,enabled,now_us(),apply_pad,NULL));
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputGetStopStatus(VauStopStatus *user_status)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        int start=!monitor_enabled;
        monitor_enabled=1;
        VauStopStatus status={sizeof(status),VAU_ABI,timeline.stop_generation,
            (uint32_t)timeline.stopped,(uint32_t)vau_stop_ready(&stop_monitor,now_us()),
            (uint32_t)stop_monitor.held,stop_monitor.error};
        rc=ksceKernelCopyToUser(user_status,&status,sizeof(status));
        ksceKernelUnlockMutex(guard,1);
        if(start) ksceKernelSetEventFlag(wake,1);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputGetObservation(VauInputObservation *user_observation)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        VauInputObservation observation={sizeof(observation),VAU_ABI,
            stop_monitor.raw_stamp,stop_monitor.previous_stamp,
            stop_monitor.observed_us,stop_monitor.changed_us,
            stop_monitor.result,stop_monitor.error,stop_monitor.mask,
            stop_monitor.buttons,stop_monitor.reason,(uint32_t)stop_monitor.sampled};
        rc=ksceKernelCopyToUser(user_observation,&observation,sizeof(observation));
        ksceKernelUnlockMutex(guard,1);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int vauInputRearm(uint64_t generation)
{
    uint32_t state;
    int rc;
    ENTER_SYSCALL(state);
    rc=enter();
    if (rc>=0) {
        uint64_t now=now_us();
        rc=leave(vau_stop_ready(&stop_monitor,now) && !stop_monitor.held ?
            vau_timeline_rearm(&timeline,generation,now,apply_pad,NULL) : VAU_DENIED);
    }
    EXIT_SYSCALL(state);
    return rc;
}
int _start(SceSize argc, const void *args) __attribute__((weak,alias("module_start")));
int module_start(SceSize argc, const void *args)
{
    (void)argc; (void)args;
    vau_timeline_init(&timeline);
    guard=ksceKernelCreateMutex("VauInputGuard",0,0,NULL);
    if (guard<0) return SCE_KERNEL_START_FAILED;
    wake=ksceKernelCreateEventFlag("VauInputWake",0,0,NULL);
    if (wake<0) goto fail;
    worker=ksceKernelCreateThread("VauInput",input_worker,0x60,0x2000,0,0,NULL);
    if (worker<0) goto fail;
    if (ksceKernelStartThread(worker,0,NULL)<0) {
        ksceKernelDeleteThread(worker);
        worker=-1;
        goto fail;
    }
    return SCE_KERNEL_START_SUCCESS;
fail:
    if (wake>=0) { ksceKernelDeleteEventFlag(wake); wake=-1; }
    ksceKernelDeleteMutex(guard);
    guard=-1;
    return SCE_KERNEL_START_FAILED;
}
int module_stop(SceSize argc, const void *args)
{
    (void)argc; (void)args;
    /* A live syscall may already be entering this module. Keep its code and
     * synchronization objects resident rather than falsely claiming quiescence.
     * Release stops input; module lifetime ends at reboot. */
    return SCE_KERNEL_STOP_CANCEL;
}
