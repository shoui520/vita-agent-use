/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "performance.h"
#include <psp2/kernel/threadmgr.h>
#include <string.h>
static struct vau_perf_watch watch;
static int guard=-1,wake=-1,worker=-1;
static void observe(struct vau_perf_observation *o)
{
    memset(o,0,sizeof(*o));
    SceKernelSystemInfo info={.size=sizeof(info)};
    o->cpu_error=sceKernelGetSystemInfo(&info);
    o->time_us=(uint64_t)sceKernelGetSystemTimeWide();
    for(unsigned i=0;i<4;i++)o->idle[i]=info.cpuInfo[i].idleClock;
    int rc=vauPerformanceRead(1,&o->raw);
    if(rc<0 || o->raw.size!=sizeof(o->raw) || o->raw.abi!=VAU_ABI) {
        memset(&o->raw,0,sizeof(o->raw));
        o->raw.foreground_error=o->raw.memory_error=o->raw.fps_error=rc<0 ? rc : VAU_DEVICE_ERROR;
    }
}
static int sampler(SceSize argc,void *args)
{
    (void)argc;(void)args;
    for(;;) {
        sceKernelWaitEventFlag(wake,1,SCE_EVENT_WAITOR|SCE_EVENT_WAITCLEAR_PAT,NULL,NULL);
        for(;;) {
            sceKernelLockMutex(guard,1,NULL);
            if(!watch.active){sceKernelUnlockMutex(guard,1);break;}
            uint64_t now=(uint64_t)sceKernelGetSystemTimeWide();
            if(now>=watch.next_us) {
                struct vau_perf_observation o;observe(&o);
                if(vau_perf_tick(&watch,&o)<0)watch.active=0;
                if(!watch.active){VauPerformanceRaw raw;vauPerformanceRead(0,&raw);}
            }
            now=(uint64_t)sceKernelGetSystemTimeWide();
            uint64_t wait=watch.next_us>now ? watch.next_us-now : 1000;
            sceKernelUnlockMutex(guard,1);
            /* The wait is event-driven; cancellation wakes it immediately. */
            unsigned timeout=(unsigned)(wait>1000000 ? 1000000 : wait);
            sceKernelWaitEventFlag(wake,1,SCE_EVENT_WAITOR|SCE_EVENT_WAITCLEAR_PAT,NULL,&timeout);
        }
    }
    return 0;
}
static int init(void)
{
    if(worker>=0)return VAU_OK;
    guard=sceKernelCreateMutex("vau_perf",0,0,NULL);if(guard<0)return guard;
    wake=sceKernelCreateEventFlag("vau_perf_wake",0,0,NULL);
    if(wake<0){int rc=wake;sceKernelDeleteMutex(guard);guard=-1;return rc;}
    worker=sceKernelCreateThread("vau_perf",sampler,0x10000100,0x4000,0,0,NULL);
    int rc=worker<0 ? worker : sceKernelStartThread(worker,0,NULL);
    if(rc<0) {
        if(worker>=0)sceKernelDeleteThread(worker);
        sceKernelDeleteEventFlag(wake);sceKernelDeleteMutex(guard);worker=wake=guard=-1;
    }
    return rc;
}
/* op: 0 measure, 1 watch, 2 read, 3 cancel. */
int vau_vita_performance(void *context,uint64_t owner,unsigned op,uint32_t value,uint32_t after,char *out,size_t cap)
{
    (void)context;int rc=init();if(rc<0)return rc;
    rc=sceKernelLockMutex(guard,1,NULL);if(rc<0)return rc;
    if(op<=1) {
        if(watch.active)rc=VAU_BUSY;
        else {
            /* Install/prime the lazy display hook before the measured window. */
            VauPerformanceRaw primed;vauPerformanceRead(1,&primed);
            struct vau_perf_observation o;observe(&o);
            rc=vau_perf_start(&watch,owner,op==0 ? value : after ? after:1000,op==0 ? value : value*1000,&o);
            if(rc<0){VauPerformanceRaw raw;vauPerformanceRead(0,&raw);}
            else sceKernelSetEventFlag(wake,1);
        }
    } else if(op==3) {
        if(watch.owner!=owner)rc=VAU_DENIED;
        else {watch.active=0;VauPerformanceRaw raw;rc=vauPerformanceRead(0,&raw);sceKernelSetEventFlag(wake,1);}
    }
    if(rc>=0)rc=vau_perf_json(&watch,owner,op<=1 ? 0:after,out,cap);
    sceKernelUnlockMutex(guard,1);return rc;
}

void vau_performance_stop(void)
{
    if(guard<0)return;
    if(sceKernelLockMutex(guard,1,NULL)<0)return;
    watch.active=0;
    VauPerformanceRaw raw;vauPerformanceRead(0,&raw);
    sceKernelSetEventFlag(wake,1);
    sceKernelUnlockMutex(guard,1);
}
