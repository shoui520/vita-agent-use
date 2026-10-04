/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "log_watch.h"
#include <psp2/io/stat.h>
#include <psp2/io/fcntl.h>
#include <string.h>
static struct vau_log_watches watches;
static int tail(void *ctx,const char *path,uint64_t offset,const void *guard,uint32_t guard_bytes,void *data,uint32_t capacity,
    uint32_t *count,uint64_t *available,int *reset)
{
    if(guard_bytes>VAU_LOG_GUARD_BYTES || guard_bytes>offset || (guard_bytes && !guard))return VAU_INVALID;
    struct vau_file_info info;
    int rc=vau_file_stat(vau_vita_file_stat,ctx,path,&info);if(rc<0)return rc;
    if(info.kind!=VAU_FILE_REGULAR || offset>INT64_MAX)return VAU_INVALID;
    int fd=sceIoOpen(path,SCE_O_RDONLY,0);if(fd<0)return fd;
    SceIoStat stat={0};rc=sceIoGetstatByFd(fd,&stat);
    if(rc>=0 && (!SCE_S_ISREG(stat.st_mode) || stat.st_size<0))rc=VAU_INVALID;
    if(rc>=0) {
        *available=(uint64_t)stat.st_size;*reset=offset>*available;
        if(!*reset && guard_bytes) {
            unsigned char observed[VAU_LOG_GUARD_BYTES];
            SceOff positioned=sceIoLseek(fd,(SceOff)(offset-guard_bytes),SCE_SEEK_SET);
            if(positioned<0)rc=(int)positioned;
            else if((uint64_t)positioned!=offset-guard_bytes)rc=VAU_DEVICE_ERROR;
            else {
                int read=sceIoRead(fd,observed,guard_bytes);
                if(read<0)rc=read;
                else if((uint32_t)read!=guard_bytes)rc=VAU_STALE;
                else if(memcmp(observed,guard,guard_bytes))*reset=1;
            }
        }
        if(*reset)offset=0;
        SceOff positioned=rc<0 ? (SceOff)rc:sceIoLseek(fd,(SceOff)offset,SCE_SEEK_SET);
        if(positioned<0)rc=(int)positioned;else if((uint64_t)positioned!=offset)rc=VAU_DEVICE_ERROR;
    }
    if(rc>=0) {
        uint64_t left=*available-offset;uint32_t wanted=left<capacity ? (uint32_t)left:capacity;
        int read=sceIoRead(fd,data,wanted);
        if(read<0)rc=read;else if((uint32_t)read>wanted)rc=VAU_DEVICE_ERROR;
        else { *count=(uint32_t)read;
            /* File shrank between stat and read: report stale and retry later;
             * append is allowed and consumed on the next bounded request. */
            if(*count<wanted)rc=VAU_STALE;
        }
    }
    int closed=sceIoClose(fd);return rc<0 ? rc:closed<0 ? closed:VAU_OK;
}
int vau_vita_log_watch(void *ctx,const char *owner,uint32_t operation,const char *path,
    const char *marker,uint32_t id,char *out,size_t cap)
{return vau_log_watch(&watches,vau_vita_file_stat,tail,ctx,owner,operation,path,marker,id,out,cap);}
