/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "native_ops.h"
#include "vau_events.h"
#include "json.h"
#include "format.h"
#include <string.h>
int vau_vita_events(void *context,uint32_t operation,uint32_t after,char *out,size_t cap)
{
    (void)context;VauDumpPage page={0};int rc=vauDumpEvents(operation,after,&page);
    if(rc<0)return rc;
    if(page.size!=sizeof(page) || page.abi!=VAU_ABI || page.count>VAU_EVENT_PAGE_COUNT)return VAU_DEVICE_ERROR;
    int n=vau_snprintf(out,cap,"{\"source\":\"native_coredump_io\",\"next\":%u,\"latest\":%u,\"more\":%s,\"lost\":%u,\"dropped\":%u,\"events\":[",page.next,page.latest,page.more ? "true":"false",page.lost,page.dropped);
    if(n<0 || (size_t)n>=cap)return VAU_DEVICE_ERROR;
    for(unsigned i=0;i<page.count;i++) {
        VauDumpEvent *e=&page.events[i];char path[1539];
        if(!memchr(e->path,0,sizeof(e->path)) || vau_json_quote(e->path,path,sizeof(path))<0)return VAU_DEVICE_ERROR;
        const char *kind=e->kind==VAU_DUMP_SAVING ? "coredump.saving" : e->kind==VAU_DUMP_COMPLETE ? "coredump.complete" : NULL;
        if(!kind)return VAU_DEVICE_ERROR;
        int added=vau_snprintf(out+n,cap-(size_t)n,"%s{\"sequence\":%u,\"type\":\"%s\",\"observed_us\":\"%llu\",\"path\":%s}",i ? ",":"",e->sequence,kind,(unsigned long long)e->observed_us,path);
        if(added<0 || (size_t)added>=cap-(size_t)n)return VAU_DEVICE_ERROR;
        n+=added;
    }
    int added=vau_snprintf(out+n,cap-(size_t)n,"]}");
    return added<0 || (size_t)added>=cap-(size_t)n ? VAU_DEVICE_ERROR : n+added;
}
