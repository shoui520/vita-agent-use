/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "performance.h"
#include "format.h"
#include "json.h"
#include <string.h>
int vau_perf_start(struct vau_perf_watch *w,uint64_t owner,uint32_t interval_ms,uint32_t duration_ms,
    const struct vau_perf_observation *o)
{
    if(!w || !o || !owner || interval_ms<100 || interval_ms>60000 || duration_ms<interval_ms || duration_ms>3600000)
        return VAU_INVALID;
    if(w->active)return VAU_BUSY;
    uint64_t generation=w->generation+1;
    memset(w,0,sizeof(*w));w->owner=owner;w->generation=generation;
    w->start_us=o->time_us;w->next_us=o->time_us+(uint64_t)interval_ms*1000;
    w->interval_us=interval_ms*1000;w->duration_us=duration_ms*1000;
    w->previous=*o;w->active=1;return VAU_OK;
}
int vau_perf_tick(struct vau_perf_watch *w,const struct vau_perf_observation *o)
{
    if(!w || !o || !w->active)return VAU_INVALID;
    if(o->time_us<w->previous.time_us)return VAU_DEVICE_ERROR;
    if(o->time_us<w->next_us)return VAU_OK;
    struct vau_perf_sample *s=&w->samples[w->count%VAU_PERF_SAMPLES];memset(s,0,sizeof(*s));
    s->index=++w->count;s->begin_us=w->previous.time_us;s->end_us=o->time_us;s->raw=o->raw;
    uint64_t elapsed=s->end_us-s->begin_us;
    s->cpu_error=o->cpu_error<0 ? o->cpu_error : w->previous.cpu_error;
    if(!elapsed)s->cpu_error=VAU_DEVICE_ERROR;
    for(unsigned i=0;i<4 && s->cpu_error>=0;i++) {
        if(o->idle[i]<w->previous.idle[i]){s->cpu_error=VAU_STALE;break;}
        uint64_t idle=o->idle[i]-w->previous.idle[i];
        s->cpu_bp[i]=idle>=elapsed ? 0 : (uint32_t)(((elapsed-idle)*10000)/elapsed);
    }
    s->fps_error=o->raw.fps_error<0 ? o->raw.fps_error : w->previous.raw.fps_error;
    if(o->raw.foreground_error<0 || w->previous.raw.foreground_error<0 || (o->raw.pid!=w->previous.raw.pid || o->raw.plane!=w->previous.raw.plane))
        s->fps_error=VAU_STALE;
    if(elapsed && s->fps_error>=0) s->fps_milli=(uint32_t)((uint64_t)(uint32_t)(o->raw.frames-w->previous.raw.frames)*1000000000/elapsed);
    w->previous=*o;
    /* Skip missed deadlines without inventing samples or accumulating drift. */
    w->next_us=w->start_us+((o->time_us-w->start_us)/w->interval_us+1)*w->interval_us;
    if(o->time_us-w->start_us>=w->duration_us)w->active=0;
    return VAU_OK;
}
int vau_perf_json(const struct vau_perf_watch *w,uint64_t owner,uint32_t after,char *out,size_t cap)
{
    if(!w->generation)return VAU_STALE;
    if(w->owner!=owner)return VAU_DENIED;
    if(after>w->count)return VAU_INVALID;
    uint32_t first=w->count>VAU_PERF_SAMPLES ? w->count-VAU_PERF_SAMPLES : 0;
    uint32_t dropped=after<first ? first-after : 0;if(after<first)after=first;
    int n=vau_snprintf(out,cap,"{\"watch_id\":\"%llu\",\"active\":%s,\"interval_ms\":%u,\"duration_ms\":%u,\"dropped_samples\":%u,\"samples\":[",
        (unsigned long long)w->generation,w->active ? "true":"false",w->interval_us/1000,w->duration_us/1000,dropped);
    if(n<0 || (size_t)n>=cap)return VAU_DEVICE_ERROR;
    unsigned emitted=0;
    for(;after<w->count && emitted<2;after++,emitted++) {
        const struct vau_perf_sample *s=&w->samples[after%VAU_PERF_SAMPLES];
        char cpu[4][24],fps[24],title[80];
        for(unsigned i=0;i<4;i++)vau_snprintf(cpu[i],sizeof(cpu[i]),"%u.%02u",s->cpu_bp[i]/100,s->cpu_bp[i]%100);
        vau_snprintf(fps,sizeof(fps),"%u.%03u",s->fps_milli/1000,s->fps_milli%1000);
        if(!memchr(s->raw.title,0,sizeof(s->raw.title)) || vau_json_quote(s->raw.title,title,sizeof(title))<0)return VAU_DEVICE_ERROR;
        int added=vau_snprintf(out+n,cap-(size_t)n,
            "%s{\"index\":%u,\"begin_us\":\"%llu\",\"end_us\":\"%llu\",\"window_us\":\"%llu\","
            "\"foreground\":{\"pid\":%d,\"title_id\":%s,\"error_code\":%d},"
            "\"cpu\":{\"scope\":\"system\",\"percent\":{\"CPU0\":%s,\"CPU1\":%s,\"CPU2\":%s,\"CPU3\":%s},\"error_code\":%d},"
            "\"fps\":{\"value\":%s,\"source\":\"framebuffer_submissions\",\"error_code\":%d},"
            "\"memory\":{\"scope\":\"foreground_partitions\",\"error_code\":%d,\"partitions\":[",
            emitted ? ",":"",s->index,(unsigned long long)s->begin_us,(unsigned long long)s->end_us,
            (unsigned long long)(s->end_us-s->begin_us),s->raw.pid,s->raw.foreground_error<0 ? "null":title,s->raw.foreground_error,
            s->cpu_error<0 ? "null":cpu[0],s->cpu_error<0 ? "null":cpu[1],s->cpu_error<0 ? "null":cpu[2],s->cpu_error<0 ? "null":cpu[3],s->cpu_error,
            s->fps_error<0 ? "null":fps,s->fps_error,s->raw.memory_error);
        if(added<0 || (size_t)added>=cap-(size_t)n)return VAU_DEVICE_ERROR;
        n+=added;
        static const char *const names[]={"USER_RW","CDRAM","PHYCONT","CDLG"};
        for(unsigned i=0;i<4;i++) {
            char total[24],free_bytes[24],used[24];
            vau_snprintf(total,sizeof(total),"%u",s->raw.total[i]);vau_snprintf(free_bytes,sizeof(free_bytes),"%u",s->raw.free[i]);
            vau_snprintf(used,sizeof(used),"%u",s->raw.total[i]-s->raw.free[i]);
            added=vau_snprintf(out+n,cap-(size_t)n,"%s{\"name\":\"%s\",\"total_bytes\":%s,\"free_bytes\":%s,\"used_bytes\":%s}",
                i ? ",":"",names[i],s->raw.memory_error<0 ? "null":total,s->raw.memory_error<0 ? "null":free_bytes,s->raw.memory_error<0 ? "null":used);
            if(added<0 || (size_t)added>=cap-(size_t)n)return VAU_DEVICE_ERROR;
        n+=added;
        }
        added=vau_snprintf(out+n,cap-(size_t)n,"]}}");
        if(added<0 || (size_t)added>=cap-(size_t)n)return VAU_DEVICE_ERROR;
        n+=added;
    }
    int added=vau_snprintf(out+n,cap-(size_t)n,"],\"next_after\":%u,\"more\":%s}",after,after<w->count ? "true":"false");
    return added<0 || (size_t)added>=cap-(size_t)n ? VAU_DEVICE_ERROR : n+added;
}
