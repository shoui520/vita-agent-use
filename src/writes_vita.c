/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "writes_vita.h"
#include "content_runtime.h"
#include "acl_config.h"
#include "format.h"
#include "json.h"
#include "file_mutations.h"
#include "config_native.h"
#include <psp2/io/fcntl.h>
#include <string.h>
extern void *vauPafMalloc(size_t);
extern void vauPafFree(void *);
#define VAU_IO_ENOENT ((int)0x80010002u)
static struct vau_service *owner;
static struct vau_file_policy policy;
void vau_vita_writes_init(struct vau_service *service) {owner=service;memset(&policy,0,sizeof(policy));}
static int stopped(void *context)
{
    struct vau_service *service=context;
    return !service || vau_service_poll(service)<0 || service->auth.stopped;
}
static uint64_t clock_us(void *context)
{(void)context;return vau_vita_native_api.clock(vau_vita_native_api.context);}
static int refresh_policy(void)
{
    memset(&policy,0,sizeof(policy));
    /* Native taiHEN precedence is ux0 then ur0. A third candidate must not
     * silently become active just because a file exists on uma0. */
    const char *configs[]={"ux0:tai/config.txt","ur0:tai/config.txt"};
    for(unsigned i=0;i<2;++i) {
        struct vau_file_info info;int rc=vau_vita_file_stat(NULL,configs[i],&info);
        if(rc==VAU_IO_ENOENT)continue;
        if(rc)return rc;
        if(info.kind!=VAU_FILE_REGULAR)return VAU_DENIED;
        policy.active_tai=i==0 ? VAU_TAI_UX0:VAU_TAI_UR0;break;
    }
    const char *path="ur0:data/vita-agent-use/acl.json";
    struct vau_file_info info;int rc=vau_vita_file_stat(NULL,path,&info);
    if(rc==VAU_IO_ENOENT) {
        struct vau_file_info backup;
        int prior=vau_vita_file_stat(NULL,"ur0:data/vita-agent-use/acl.previous.json",&backup);
        if(prior==VAU_IO_ENOENT)return VAU_OK; /* No previous owner ACL. */
        if(prior || backup.kind!=VAU_FILE_REGULAR)return VAU_DENIED;
        if(stopped(owner))return VAU_DENIED;
        rc=sceIoRename("ur0:data/vita-agent-use/acl.previous.json",path);
        if(!rc)rc=vau_vita_file_stat(NULL,path,&info);
    }
    if(rc)return rc;
    if(info.kind!=VAU_FILE_REGULAR || !info.bytes || info.bytes>VAU_ACL_CONFIG_BYTES)return VAU_DENIED;
    char *json=vauPafMalloc((size_t)info.bytes+1);if(!json)return VAU_DEVICE_ERROR;
    int fd=sceIoOpen(path,SCE_O_RDONLY,0);size_t used=0;
    if(fd<0)rc=fd;
    while(!rc && used<info.bytes) {
        if(stopped(owner)){rc=VAU_DENIED;break;}
        int n=sceIoRead(fd,json+used,(unsigned)(info.bytes-used));
        if(n<=0 || (uint64_t)n>info.bytes-used){rc=n<0 ? n:VAU_STALE;break;}used+=(unsigned)n;
    }
    if(!rc){char extra;int n=sceIoRead(fd,&extra,1);if(n)rc=n<0 ? n:VAU_STALE;}
    if(fd>=0){int closed=sceIoClose(fd);if(!rc && closed<0)rc=closed;}
    if(!rc)rc=vau_acl_config_parse(json,used,policy.active_tai,&policy);
    vauPafFree(json);return rc;
}
static int open_journal(const struct vau_write_request *request,struct vau_write_journal *journal,int recover,int readonly)
{
    if(!owner || !request || stopped(owner))return VAU_DENIED;
    int rc=refresh_policy();if(rc)return rc;
    /* New writes require current ACLs before journal creation. Recovery opens
     * an existing journal only; bound identity/intent and absolute protections
     * are checked by the recovery coordinator before any restoration. */
    if(!recover && vau_policy_evaluate(&policy,request->subject,request->operation,request->path,(int)request->yes)!=VAU_POLICY_ALLOW)return VAU_DENIED;
    if(!recover && request->operation==VAU_FS_RENAME_SOURCE &&
        vau_policy_evaluate(&policy,request->subject,VAU_FS_RENAME_DESTINATION,request->destination,(int)request->yes)!=VAU_POLICY_ALLOW)return VAU_DENIED;
    struct vau_file_info info;rc=vau_vita_file_stat(NULL,"ur0:data/vita-agent-use",&info);if(rc)return rc;
    if(info.kind!=VAU_FILE_DIRECTORY)return VAU_DENIED;
    const char *path="ur0:data/vita-agent-use/write-audit.db";
    rc=vau_vita_file_stat(NULL,path,&info);
    if(rc && (recover || readonly || rc!=VAU_IO_ENOENT))return rc;
    if(!rc && info.kind!=VAU_FILE_REGULAR)return VAU_DENIED;
    if(stopped(owner))return VAU_DENIED;
    return readonly ? vau_journal_open_readonly(journal,path):vau_journal_open(journal,path);
}
int vau_vita_file_mutate(void *context,const struct vau_write_request *request,struct vau_write_record *out)
{
    (void)context;
    if(!out || !request)return VAU_INVALID;
    memset(out,0,sizeof(*out));
    if(vau_vita_content_busy())return VAU_BUSY;
    if(request->operation!=VAU_FS_MKDIR && request->operation!=VAU_FS_RENAME_SOURCE && request->operation!=VAU_FS_TRASH && request->operation!=VAU_FS_PURGE)return VAU_UNSUPPORTED;
    int reset=vau_vita_file_list_reset();if(reset<0)return reset;
    struct vau_write_journal journal={0};int rc=open_journal(request,&journal,0,0);if(rc)return rc;
    struct vau_upload_context upload={.policy=&policy,.journal=&journal,.context=owner,.stopped=stopped,.clock=clock_us};
    rc=vau_mutation_execute(&upload,request,out);
    int closed=vau_journal_close(&journal);return closed ? closed:rc;
}
int vau_vita_file_upload(void *context,const struct vau_upload_message *m,struct vau_upload_status *status,struct vau_write_record *out)
{
    (void)context;
    if(!m || !status || !out || (unsigned)m->action>VAU_UPLOAD_RECOVER)return VAU_INVALID;
    memset(status,0,sizeof(*status));memset(out,0,sizeof(*out));
    if(vau_vita_content_busy())return VAU_BUSY;
    int reset=vau_vita_file_list_reset();if(reset<0)return reset;
    const struct vau_write_request *r=&m->request;
    if(r->operation!=VAU_FS_WRITE)return VAU_INVALID;
    uint64_t begin=clock_us(NULL);
    struct vau_write_journal journal={0};
    int rc=open_journal(r,&journal,m->action==VAU_UPLOAD_RECOVER,m->action==VAU_UPLOAD_CHUNK);
    uint64_t opened=clock_us(NULL);
    if(rc){status->journal_open_us=opened>=begin ? opened-begin:0;return rc;}
    struct vau_upload_context upload={.policy=&policy,.journal=&journal,.context=owner,.stopped=stopped,.clock=clock_us,
        .config_check=vau_config_native_preflight,.config_replace=vau_upload_config_replace};
    rc=vau_journal_state(&journal,r->subject,r->id,out);
    if(!rc && !vau_write_request_same(r,&out->request))rc=VAU_STALE;
    else if(!rc && out->phase==VAU_WRITE_COMPLETE)rc=out->result;
    else if(rc==1 || (!rc && out->phase!=VAU_WRITE_COMPLETE)) {
        if(m->action==VAU_UPLOAD_BEGIN)rc=vau_upload_begin(&upload,r,status);
        else if(m->action==VAU_UPLOAD_CHUNK)rc=vau_upload_chunk(&upload,r,m->offset,m->data,m->data_bytes,status);
        else if(m->action==VAU_UPLOAD_VERIFY)rc=vau_upload_verify(&upload,r,status);
        else if(m->action==VAU_UPLOAD_COMMIT)rc=vau_upload_commit(&upload,r,out);
        else rc=vau_upload_recover(&upload,r,out);
    }
    if(!rc && out->phase==VAU_WRITE_COMPLETE && out->sequence){status->received=r->bytes;status->verified=1;}
    uint64_t worked=clock_us(NULL);
    int closed=vau_journal_close(&journal);
    uint64_t ended=clock_us(NULL);
    status->journal_open_us=opened>=begin ? opened-begin:0;
    status->work_us=worked>=opened ? worked-opened:0;
    status->journal_close_us=ended>=worked ? ended-worked:0;
    return closed ? closed:rc;
}

int vau_vita_acl_load(struct vau_file_policy *out)
{
    if(!out || stopped(owner))return VAU_DENIED;
    int rc=refresh_policy();if(!rc)*out=policy;return rc;
}
int vau_vita_acl_store(const struct vau_file_policy *updated)
{
    if(!updated || stopped(owner))return VAU_DENIED;
    char *json=vauPafMalloc(VAU_ACL_CONFIG_BYTES);if(!json)return VAU_DEVICE_ERROR;
    int n=vau_acl_config_format(updated,json,VAU_ACL_CONFIG_BYTES),rc=n<0 ? n:0;
    const char *tmp="ur0:data/vita-agent-use/acl.pending.json";
    const char *path="ur0:data/vita-agent-use/acl.json";
    int fd=-1;
    if(!rc){fd=sceIoOpen(tmp,SCE_O_WRONLY|SCE_O_CREAT|SCE_O_TRUNC,0666);if(fd<0)rc=fd;}
    size_t used=0;
    while(!rc && used<(size_t)n) {
        if(stopped(owner)){rc=VAU_DENIED;break;}
        int wrote=sceIoWrite(fd,json+used,(unsigned)((size_t)n-used));
        if(wrote<=0 || (size_t)wrote>(size_t)n-used){rc=wrote<0 ? wrote:VAU_DEVICE_ERROR;break;}used+=(size_t)wrote;
    }
    if(fd>=0){int closed=sceIoClose(fd);if(!rc && closed<0)rc=closed;}
    if(!rc)rc=sceIoSync("ur0:",0);
    /* Vita rename rejects an existing destination. Retain the old ACL until
     * the staged document is installed; restore it if installation fails. */
    const char *backup="ur0:data/vita-agent-use/acl.previous.json";
    int retained=0;
    if(!rc && stopped(owner))rc=VAU_DENIED;
    struct vau_file_info prior;
    if(!rc) {
        int exists=vau_vita_file_stat(NULL,path,&prior);
        if(!exists) {
            int removed=sceIoRemove(backup);
            if(removed && removed!=VAU_IO_ENOENT)rc=removed;
            if(!rc){rc=sceIoRename(path,backup);retained=!rc;}
        } else if(exists!=VAU_IO_ENOENT)rc=exists;
    }
    if(!rc) {
        rc=sceIoRename(tmp,path);
        if(rc && retained) {
            int restored=sceIoRename(backup,path);
            if(restored)rc=restored;
        }
    }
    if(!rc)rc=sceIoSync("ur0:",0);
    if(!rc)rc=refresh_policy();
    if(!rc && memcmp(updated,&policy,sizeof(policy)))rc=VAU_STALE;
    vauPafFree(json);return rc;
}

int vau_vita_acl_audit(const char *subject,const char *id,const char *path,const char *phase,int result)
{
    char quoted[VAU_PATH_MAX*6+3],line[VAU_PATH_MAX*6+512];
    if(vau_json_quote(path,quoted,sizeof(quoted))<0)return VAU_INVALID;
    int n=vau_snprintf(line,sizeof(line),"{\"request_id\":\"%s\",\"subject\":\"%s\",\"path\":%s,\"operation\":\"acl.grant_write\",\"phase\":\"%s\",\"result\":%d,\"observed_us\":\"%llu\"}\n",id,subject,quoted,phase,result,(unsigned long long)clock_us(NULL));
    if(n<0 || (size_t)n>=sizeof(line))return VAU_INVALID;
    int fd=sceIoOpen("ur0:data/vita-agent-use/acl-audit.jsonl",SCE_O_WRONLY|SCE_O_CREAT|SCE_O_APPEND,0666);
    if(fd<0)return fd;
    int rc=0;size_t used=0;
    while(used<(size_t)n) {
        int wrote=sceIoWrite(fd,line+used,(unsigned)((size_t)n-used));
        if(wrote<=0 || (size_t)wrote>(size_t)n-used){rc=wrote<0 ? wrote:VAU_DEVICE_ERROR;break;}used+=(size_t)wrote;
    }
    int closed=sceIoClose(fd);if(!rc && closed<0)rc=closed;
    if(!rc)rc=sceIoSync("ur0:",0);
    return rc;
}
int vau_vita_acl_audit_read(void *ctx,uint32_t offset,char *out,size_t capacity)
{
    (void)ctx;
    if(!out || capacity<1025 || stopped(owner))return VAU_DENIED;
    int fd=sceIoOpen("ur0:data/vita-agent-use/acl-audit.jsonl",SCE_O_RDONLY,0);
    if(fd==VAU_IO_ENOENT){out[0]=0;return 0;}if(fd<0)return fd;
    int rc=0;
    if(sceIoLseek(fd,offset,SCE_SEEK_SET)!=(int64_t)offset)rc=VAU_DEVICE_ERROR;
    if(!rc) {
        rc=sceIoRead(fd,out,1024);
        if(rc==1024) {
            unsigned start=1023;
            while(start && ((unsigned char)out[start]&0xc0)==0x80)--start;
            unsigned char c=(unsigned char)out[start];
            unsigned need=c>=0xf0 ? 4:c>=0xe0 ? 3:c>=0xc0 ? 2:1;
            if(1024-start<need)rc=(int)start;
        }
        if(rc>=0){if(memchr(out,0,(size_t)rc))rc=VAU_DEVICE_ERROR;else out[rc]=0;}
    }
    int closed=sceIoClose(fd);return closed<0 ? closed:rc;
}
