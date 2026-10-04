/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "log_marker.h"
#include "vita_agent.h"
#include <string.h>
int vau_log_marker_init(struct vau_log_marker *m,const void *text,size_t size,uint64_t offset)
{
    if(!m || !text || !size || size>VAU_LOG_MARKER_BYTES)return VAU_INVALID;
    memset(m,0,sizeof(*m));memcpy(m->text,text,size);m->length=(uint32_t)size;m->offset=offset;
    for(unsigned i=1,k=0;i<size;i++) {
        while(k && m->text[i]!=m->text[k])k=m->prefix[k-1];
        if(m->text[i]==m->text[k])++k;
        m->prefix[i]=(uint8_t)k;
    }
    return VAU_OK;
}
size_t vau_log_marker_feed(struct vau_log_marker *m,const void *data,size_t size,uint64_t *ends,size_t capacity)
{
    if(!m || !m->length || (!data && size) || (!ends && capacity) || size>UINT64_MAX-m->offset)return 0;
    const unsigned char *bytes=data;size_t written=0;
    for(size_t i=0;i<size;i++) {
        while(m->matched && bytes[i]!=m->text[m->matched])m->matched=m->prefix[m->matched-1];
        if(bytes[i]==m->text[m->matched])++m->matched;
        if(m->matched==m->length) {
            if(written<capacity)ends[written++]=m->offset+i+1;
            ++m->hits;m->matched=m->prefix[m->length-1];
        }
    }
    m->offset+=size;return written;
}
