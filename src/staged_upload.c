/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "staged_upload.h"
#include "file_ops.h"
#include "format.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <mbedtls/sha256.h>
#include <string.h>
extern void *vauPafMalloc(size_t);
extern void vauPafFree(void *);
#define VAU_IO_ENOENT ((int)0x80010002u)
#define VAU_IO_EEXIST ((int)0x80010011u)
static int hex(const char *p,unsigned n)
{ for(unsigned i=0;i<n;++i)if(!((p[i]>='0'&&p[i]<='9') || (p[i]>='a'&&p[i]<='f')))return 0;return !p[n]; }
int vau_upload_stage_path(const struct vau_write_request *r,char out[VAU_PATH_MAX])
{
    if(!r || !out || !memchr(r->path,0,sizeof(r->path)) ||
        !memchr(r->id,0,sizeof(r->id)) || !memchr(r->subject,0,sizeof(r->subject)) ||
        !hex(r->id,32) || !hex(r->subject,64))return VAU_INVALID;
    char path[VAU_PATH_MAX];if(vau_path_normalize(r->path,path,sizeof(path)))return VAU_INVALID;
    const char *colon=strchr(path,':');char mount[9]={0};memcpy(mount,path,(size_t)(colon-path));
    int n=vau_snprintf(out,VAU_PATH_MAX,"%s:data/vita-agent-use/transactions/%s_%s.part",mount,r->subject,r->id);
    return n>0 && n<(int)VAU_PATH_MAX ? VAU_OK:VAU_INVALID;
}
static int gate(struct vau_upload_context *c,const struct vau_write_request *r)
{
    if(!c || !c->journal || !c->policy || !c->clock || !c->stopped || !r ||
        r->operation!=VAU_FS_WRITE || !memchr(r->path,0,sizeof(r->path)) ||
        !memchr(r->sha256,0,sizeof(r->sha256)) || !hex(r->sha256,64) ||
        !memchr(r->expected_sha256,0,sizeof(r->expected_sha256)) ||
        (r->overwrite ? (*r->expected_sha256 && !hex(r->expected_sha256,64)):!!*r->expected_sha256) ||
        !memchr(r->destination,0,sizeof(r->destination)) || *r->destination ||
        r->yes>1 || r->recursive || r->overwrite>1 || r->bytes>INT64_MAX)return VAU_INVALID;
    if(r->overwrite && !r->yes)return VAU_DENIED;
    char stage[VAU_PATH_MAX];if(vau_upload_stage_path(r,stage))return VAU_INVALID;
    if(vau_policy_evaluate(c->policy,r->subject,VAU_FS_WRITE,r->path,(int)r->yes)!=VAU_POLICY_ALLOW ||
        c->stopped(c->context))return VAU_DENIED;
    return VAU_OK;
}
static int audit(struct vau_upload_context *c,const struct vau_write_request *r,const char *detail,uint64_t offset,int started)
{
    struct vau_write_record record={.request=*r,.phase=VAU_WRITE_PROGRESS,.offset=offset,
        .observed_us=c->clock(c->context),.effect_started=(unsigned)started,.result=VAU_BUSY};
    strcpy(record.detail,detail);return vau_journal_append(c->journal,&record);
}
static int state(struct vau_upload_context *c,const struct vau_write_request *r)
{
    struct vau_write_record record;int rc=vau_journal_state(c->journal,r->subject,r->id,&record);
    if(rc)return rc==1 ? VAU_STALE:rc;
    return record.phase==VAU_WRITE_PREPARE && vau_write_request_same(r,&record.request) ? VAU_OK:VAU_STALE;
}
static int stat_regular(const char *path,struct vau_file_info *info)
{
    int rc=vau_vita_file_stat(NULL,path,info);
    return rc<0 ? rc:info->kind==VAU_FILE_REGULAR ? VAU_OK:VAU_DENIED;
}
static int parent(const char *path,char out[VAU_PATH_MAX])
{
    strcpy(out,path);char *slash=strrchr(out,'/');
    if(slash)*slash=0;else {char *colon=strchr(out,':');if(!colon)return VAU_INVALID;colon[1]=0;}
    struct vau_file_info info;int rc=vau_vita_file_stat(NULL,out,&info);
    return rc<0 ? rc:info.kind==VAU_FILE_DIRECTORY ? VAU_OK:VAU_INVALID;
}
static int open_checked(const char *path,int flags,const struct vau_file_info *before)
{
    int fd=sceIoOpen(path,flags,0);if(fd<0)return fd;
    SceIoStat opened={0};int rc=sceIoGetstatByFd(fd,&opened);
    SceDateTime time={before->year,before->month,before->day,before->hour,before->minute,before->second,before->microsecond};
    if(rc>=0 && (!SCE_S_ISREG(opened.st_mode) || opened.st_size<0 || (uint64_t)opened.st_size!=before->bytes ||
        memcmp(&opened.st_mtime,&time,sizeof(time))))rc=VAU_STALE;
    if(rc<0){sceIoClose(fd);return rc;}return fd;
}
int vau_upload_file_digest(struct vau_upload_context *c,const char *path,char out[65])
{
    if(!c || !c->stopped || !out)return VAU_INVALID;
    out[0]=0;
    struct vau_file_info before,after;int rc=stat_regular(path,&before);if(rc<0)return rc;
    int fd=open_checked(path,SCE_O_RDONLY,&before);if(fd<0)return fd;
    unsigned char *buffer=vauPafMalloc(VAU_FILE_READ_BYTES);if(!buffer){sceIoClose(fd);return VAU_DEVICE_ERROR;}
    mbedtls_sha256_context hash;mbedtls_sha256_init(&hash);rc=mbedtls_sha256_starts(&hash,0);
    uint64_t count=0;unsigned char digest[32];
    while(!rc && count<before.bytes) {
        if(c->stopped(c->context)){rc=VAU_DENIED;break;}
        uint64_t left=before.bytes-count;unsigned wanted=left<VAU_FILE_READ_BYTES ? (unsigned)left:VAU_FILE_READ_BYTES;
        int got=sceIoRead(fd,buffer,wanted);
        if(got<0)rc=got;else if(!got || (unsigned)got>wanted)rc=VAU_STALE;
        else {rc=mbedtls_sha256_update(&hash,buffer,(size_t)got);count+=(unsigned)got;}
    }
    if(!rc)rc=mbedtls_sha256_finish(&hash,digest);
    mbedtls_sha256_free(&hash);vauPafFree(buffer);
    int closed=sceIoClose(fd);if(!rc && closed<0)rc=closed;
    if(!rc)rc=stat_regular(path,&after);
    if(!rc && (before.bytes!=after.bytes || before.mode!=after.mode || before.year!=after.year || before.month!=after.month ||
        before.day!=after.day || before.hour!=after.hour || before.minute!=after.minute || before.second!=after.second ||
        before.microsecond!=after.microsecond))rc=VAU_STALE;
    if(rc)return rc<0 ? rc:VAU_DEVICE_ERROR;
    static const char hexchars[]="0123456789abcdef";
    for(unsigned i=0;i<32;++i){out[i*2]=hexchars[digest[i]>>4];out[i*2+1]=hexchars[digest[i]&15];}out[64]=0;return VAU_OK;
}
static int directories(struct vau_upload_context *c,const struct vau_write_request *r,const char *stage)
{
    char p[VAU_PATH_MAX];strcpy(p,stage);
    for(size_t i=0;p[i];++i)if(p[i]=='/') {
        p[i]=0;struct vau_file_info info;int rc=vau_vita_file_stat(NULL,p,&info);
        if(rc==VAU_IO_ENOENT) {
            if(c->stopped(c->context)){p[i]='/';return VAU_DENIED;}
            rc=audit(c,r,"stage_mkdir_intent",0,0);
            if(!rc && c->stopped(c->context))rc=VAU_DENIED;
            if(!rc)rc=sceIoMkdir(p,0777);
            if(!rc)rc=audit(c,r,"stage_mkdir",0,1);
            if(rc==VAU_IO_EEXIST)rc=vau_vita_file_stat(NULL,p,&info);
            else if(!rc){info.kind=VAU_FILE_DIRECTORY;}
        }
        p[i]='/';if(rc<0)return rc;if(info.kind!=VAU_FILE_DIRECTORY)return VAU_DENIED;
    }
    return VAU_OK;
}
int vau_upload_begin(struct vau_upload_context *c,const struct vau_write_request *r,struct vau_upload_status *out)
{
    if(!out)return VAU_INVALID;
    memset(out,0,sizeof(*out));int rc=gate(c,r);if(rc)return rc;
    char p[VAU_PATH_MAX],stage[VAU_PATH_MAX];rc=parent(r->path,p);if(rc)return rc;
    struct vau_file_info target;rc=stat_regular(r->path,&target);
    if(rc==VAU_IO_ENOENT){if(r->overwrite && *r->expected_sha256)return VAU_STALE;}
    else if(rc<0)return rc;
    else {
        if(!r->overwrite)return VAU_STALE;
        if(*r->expected_sha256){char digest[65];rc=vau_upload_file_digest(c,r->path,digest);if(rc)return rc;if(strcmp(digest,r->expected_sha256))return VAU_STALE;}
    }
    struct vau_write_record previous;rc=vau_journal_state(c->journal,r->subject,r->id,&previous);
    if(rc==1) {
        struct vau_write_record record={.request=*r,.phase=VAU_WRITE_PREPARE,.result=VAU_BUSY,.observed_us=c->clock(c->context)};
        rc=vau_journal_append(c->journal,&record);
    } else if(!rc && (previous.phase!=VAU_WRITE_PREPARE || !vau_write_request_same(r,&previous.request)))rc=VAU_STALE;
    if(rc)return rc;
    rc=vau_upload_stage_path(r,stage);if(rc)return rc;
    rc=stat_regular(stage,&target);
    if(!rc){if(target.bytes>r->bytes)return VAU_STALE;out->received=target.bytes;return VAU_OK;}
    if(rc!=VAU_IO_ENOENT)return rc;
    rc=directories(c,r,stage);if(rc)return rc;
    if(c->stopped(c->context))return VAU_DENIED;
    rc=audit(c,r,"stage_create_intent",0,0);if(rc)return rc;
    if(c->stopped(c->context))return VAU_DENIED;
    int fd=sceIoOpen(stage,SCE_O_RDWR|SCE_O_CREAT|SCE_O_EXCL,0777);if(fd<0)return fd;
    rc=sceIoSyncByFd(fd,0);int closed=sceIoClose(fd);if(rc>=0 && closed<0)rc=closed;
    return rc<0 ? rc:audit(c,r,"stage_create",0,1);
}
int vau_upload_chunk(struct vau_upload_context *c,const struct vau_write_request *r,uint64_t offset,
    const void *data,uint32_t bytes,struct vau_upload_status *out)
{
    if(!out)return VAU_INVALID;
    memset(out,0,sizeof(*out));
    int rc=gate(c,r);if(rc)return rc;
    if(!data || !bytes || bytes>VAU_UPLOAD_CHUNK_BYTES || offset>r->bytes || bytes>r->bytes-offset)return VAU_INVALID;
    rc=state(c,r);if(rc)return rc;
    char stage[VAU_PATH_MAX];rc=vau_upload_stage_path(r,stage);if(rc)return rc;
    struct vau_file_info before;rc=stat_regular(stage,&before);if(rc)return rc;
    if(before.bytes>r->bytes || offset>before.bytes)return VAU_STALE;
    int fd=open_checked(stage,SCE_O_RDWR,&before);if(fd<0)return fd;
    SceOff position=sceIoLseek(fd,(SceOff)offset,SCE_SEEK_SET);
    if(position<0 || (uint64_t)position!=offset){sceIoClose(fd);return position<0 ? (int)position:VAU_DEVICE_ERROR;}
    uint64_t old=before.bytes-offset;uint32_t overlap=old<bytes ? (uint32_t)old:bytes,at=0;
    unsigned scratch=overlap<VAU_FILE_READ_BYTES ? overlap:VAU_FILE_READ_BYTES;
    unsigned char *buffer=scratch ? vauPafMalloc(scratch):NULL;
    if(scratch && !buffer){sceIoClose(fd);return VAU_DEVICE_ERROR;}
    while(at<overlap) {
        if(c->stopped(c->context)){rc=VAU_DENIED;break;}
        unsigned wanted=overlap-at;if(wanted>scratch)wanted=scratch;
        int got=sceIoRead(fd,buffer,wanted);
        if(got<0){rc=got;break;}
        if(!got || (unsigned)got>wanted){rc=VAU_STALE;break;}
        if(memcmp(buffer,(const unsigned char *)data+at,(size_t)got)){rc=VAU_STALE;break;}
        at+=(unsigned)got;
    }
    if(buffer)vauPafFree(buffer);
    /* PREPARE/stage_create durably bind the whole private upload before
     * chunks are accepted. Audit logical staging at begin/verify, rather
     * than creating two SQLite FULL-sync transactions per wire packet. */
    while(!rc && at<bytes) {
        if(c->stopped(c->context)){rc=VAU_DENIED;break;}
        unsigned wanted=bytes-at;if(wanted>VAU_FILE_READ_BYTES)wanted=VAU_FILE_READ_BYTES;
        int written=sceIoWrite(fd,(const unsigned char *)data+at,wanted);
        if(written<0)rc=written;else if(!written || (unsigned)written>wanted)rc=VAU_DEVICE_ERROR;else at+=(unsigned)written;
    }
    if(!rc)rc=sceIoSyncByFd(fd,0);
    int closed=sceIoClose(fd);if(!rc && closed<0)rc=closed;
    if(rc)return rc<0 ? rc:VAU_DEVICE_ERROR;
    out->received=before.bytes>offset+bytes ? before.bytes:offset+bytes;return VAU_OK;
}
int vau_upload_verify(struct vau_upload_context *c,const struct vau_write_request *r,struct vau_upload_status *out)
{
    if(!out)return VAU_INVALID;
    memset(out,0,sizeof(*out));int rc=gate(c,r);if(rc)return rc;
    rc=state(c,r);if(rc)return rc;
    char stage[VAU_PATH_MAX],digest[65];rc=vau_upload_stage_path(r,stage);if(rc)return rc;
    struct vau_file_info info;rc=stat_regular(stage,&info);if(rc)return rc;out->received=info.bytes;
    if(info.bytes!=r->bytes)return VAU_STALE;
    rc=vau_upload_file_digest(c,stage,digest);if(rc)return rc;
    if(strcmp(digest,r->sha256))return VAU_STALE;
    rc=audit(c,r,"stage_verified",r->bytes,1);if(rc)return rc;
    out->verified=1;return VAU_OK;
}
