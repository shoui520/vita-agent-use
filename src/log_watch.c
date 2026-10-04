/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "log_watch.h"
#include "json.h"
#include "format.h"
#include <string.h>
int vau_log_watch(struct vau_log_watches *w,vau_file_stat_fn stat,vau_log_tail_fn tail,void *ctx,
    const char *owner,uint32_t operation,const char *path,const char *marker,uint32_t id,char *out,size_t cap)
{
    if(!w || !owner || strlen(owner)!=64 || !out || cap<3500 || operation>2)return VAU_INVALID;
    struct vau_log_watch_slot *slot=NULL;
    if(operation==0) {
        char normalized[VAU_PATH_MAX];struct vau_file_info info;
        if(!marker || !marker[0] || strlen(marker)>VAU_LOG_MARKER_BYTES ||
            vau_path_normalize(path,normalized,sizeof(normalized)))return VAU_INVALID;
        int rc=vau_file_stat(stat,ctx,normalized,&info);
        if((uint32_t)rc==UINT32_C(0x80010002))info=(struct vau_file_info){.kind=VAU_FILE_REGULAR};
        else if(rc<0)return rc;
        if(info.kind!=VAU_FILE_REGULAR)return VAU_INVALID;
        for(unsigned i=0;i<VAU_LOG_WATCHES;i++)if(!w->slots[i].id){slot=&w->slots[i];break;}
        if(!slot || w->next==UINT32_MAX)return VAU_BUSY;
        char quoted[VAU_PATH_MAX*6+3];if(vau_json_quote(normalized,quoted,sizeof(quoted))<0)return VAU_INVALID;
        if(!tail)return VAU_UNSUPPORTED;
        unsigned char guard[VAU_LOG_GUARD_BYTES];
        uint32_t guard_bytes=info.bytes<sizeof(guard) ? (uint32_t)info.bytes:sizeof(guard);
        if(guard_bytes) {
            uint32_t count=0;uint64_t available=0;int reset=0;
            rc=tail(ctx,normalized,info.bytes-guard_bytes,NULL,0,guard,guard_bytes,&count,&available,&reset);
            if(rc<0)return rc;
            if(reset || count!=guard_bytes || available<info.bytes)return VAU_STALE;
        }
        uint32_t next=w->next+1;
        int n=vau_snprintf(out,cap,"{\"watch_id\":%u,\"path\":%s,\"offset\":\"%llu\",\"from\":\"end\",\"chunk_bytes_max\":768}",next,quoted,(unsigned long long)info.bytes);
        if(n<0 || (size_t)n>=cap)return VAU_DEVICE_ERROR;
        *slot=(struct vau_log_watch_slot){.id=next};
        memcpy(slot->owner,owner,65);memcpy(slot->path,normalized,strlen(normalized)+1);
        rc=vau_log_marker_init(&slot->marker,marker,strlen(marker),info.bytes);
        if(rc){memset(slot,0,sizeof(*slot));return rc;}
        memcpy(slot->guard,guard,guard_bytes);slot->guard_bytes=guard_bytes;
        w->next=next;return n;
    }
    for(unsigned i=0;i<VAU_LOG_WATCHES;i++)if(w->slots[i].id==id && !strcmp(w->slots[i].owner,owner)){slot=&w->slots[i];break;}
    if(!slot)return VAU_DENIED;
    if(operation==2) {
        int n=vau_snprintf(out,cap,"{\"watch_id\":%u,\"stopped\":true}",id);
        if(n<0 || (size_t)n>=cap)return VAU_DEVICE_ERROR;
        memset(slot,0,sizeof(*slot));return n;
    }
    if(vau_policy_file(VAU_FS_READ,slot->path)!=VAU_POLICY_ALLOW)return VAU_DENIED;
    if(!tail)return VAU_UNSUPPORTED;
    unsigned char data[VAU_LOG_CHUNK];uint32_t count=0;uint64_t available=0;int reset=0;
    uint64_t start=slot->marker.offset;
    int rc=tail(ctx,slot->path,start,slot->guard,slot->guard_bytes,data,sizeof(data),&count,&available,&reset);
    if(rc<0)return rc;
    if(count>sizeof(data) || (reset!=0 && reset!=1))return VAU_DEVICE_ERROR;
    if(reset)start=0;
    if(start>available || count>available-start || start>UINT64_MAX-count)return VAU_DEVICE_ERROR;
    struct vau_log_marker next=slot->marker;
    if(reset){next.offset=0;next.matched=0;}
    uint64_t before=next.hits,ends[8];size_t emitted=vau_log_marker_feed(&next,data,count,ends,8);
    char hex[VAU_LOG_CHUNK*2+1];static const char digits[]="0123456789abcdef";
    for(unsigned i=0;i<count;i++){hex[2*i]=digits[data[i]>>4];hex[2*i+1]=digits[data[i]&15];}hex[2*count]=0;
    int n=vau_snprintf(out,cap,"{\"watch_id\":%u,\"offset\":\"%llu\",\"next_offset\":\"%llu\",\"reset\":%s,\"more\":%s,\"encoding\":\"hex\",\"data\":\"%s\",\"marker_hits\":\"%llu\",\"marker_ends\":[",id,(unsigned long long)start,(unsigned long long)next.offset,reset ? "true":"false",next.offset<available ? "true":"false",hex,(unsigned long long)(next.hits-before));
    if(n<0 || (size_t)n>=cap)return VAU_DEVICE_ERROR;
    for(size_t i=0;i<emitted;i++) {
        int added=vau_snprintf(out+n,cap-(size_t)n,"%s\"%llu\"",i ? ",":"",(unsigned long long)ends[i]);
        if(added<0 || (size_t)added>=cap-(size_t)n)return VAU_DEVICE_ERROR;
        n+=added;
    }
    int added=vau_snprintf(out+n,cap-(size_t)n,"],\"marker_offsets_omitted\":\"%llu\"}",(unsigned long long)(next.hits-before-emitted));
    if(added<0 || (size_t)added>=cap-(size_t)n)return VAU_DEVICE_ERROR;
    /* Commit the cursor and its guard together, only after a complete reply. */
    uint32_t kept=reset ? 0:slot->guard_bytes;
    if(count>=VAU_LOG_GUARD_BYTES) {
        memcpy(slot->guard,data+count-VAU_LOG_GUARD_BYTES,VAU_LOG_GUARD_BYTES);
        kept=VAU_LOG_GUARD_BYTES;
    } else {
        if(kept>VAU_LOG_GUARD_BYTES-count)kept=VAU_LOG_GUARD_BYTES-count;
        if(kept)memmove(slot->guard,slot->guard+slot->guard_bytes-kept,kept);
        memcpy(slot->guard+kept,data,count);kept+=count;
    }
    slot->guard_bytes=kept;slot->marker=next;return n+added;
}
