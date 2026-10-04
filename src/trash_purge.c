/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "file_mutations.h"
#include "file_tree.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <string.h>
struct purge_context {
    struct vau_upload_context *upload;
    char physical[VAU_PATH_MAX];
    const struct vau_write_request *request;
    vau_write_visit visitor;void *visit_context;
    unsigned *started;
};
static int provenance(struct purge_context *p,const struct vau_write_request *r)
{
    struct vau_write_record trash;int rc=vau_journal_lookup(p->upload->journal,r->subject,r->trash_id,&trash);
    if(rc)return rc==1 ? VAU_DENIED:rc;
    if(trash.phase!=VAU_WRITE_COMPLETE || trash.result || !trash.effect_started ||
        trash.request.operation!=VAU_FS_TRASH)return VAU_DENIED;
    struct vau_write_request bound=trash.request;strcpy(bound.path,r->path);
    if(!vau_write_request_same(&bound,&trash.request))return VAU_DENIED;
    p->request=r;return vau_mutation_trash_path(&trash.request,p->physical);
}
static int logical(struct purge_context *p,const char *physical,char path[VAU_PATH_MAX])
{
    size_t base=strlen(p->physical),root=strlen(p->request->path),length=strlen(physical);
    if(length<base || memcmp(physical,p->physical,base) || (physical[base] && physical[base]!='/') || root+length-base>=VAU_PATH_MAX)return VAU_INVALID;
    memcpy(path,p->request->path,root);memcpy(path+root,physical+base,length-base+1);return VAU_OK;
}
static int preflight_visit(void *opaque,const char *physical,const struct vau_file_info *info)
{
    (void)info;struct purge_context *p=opaque;char path[VAU_PATH_MAX];int rc=logical(p,physical,path);
    return rc ? rc:p->visitor(p->visit_context,path);
}
static int preflight(void *opaque,const struct vau_write_request *r,vau_write_visit visitor,void *context)
{
    struct purge_context *p=opaque;int rc=provenance(p,r);if(rc)return rc;
    p->visitor=visitor;p->visit_context=context;
    return vau_native_tree_walk(p->physical,0,preflight_visit,p,p->upload->stopped,p->upload->context);
}
static int event(struct purge_context *p,const char *step,const char *path,const char *physical,int result,
    const struct vau_write_observation *before,const struct vau_write_observation *after)
{
    struct vau_write_record record={.request=*p->request,.phase=VAU_WRITE_PROGRESS,.result=result,
        .effect_started=*p->started,.observed_us=p->upload->clock(p->upload->context)};
    strcpy(record.detail,step);strcpy(record.detail_path,path);
    strcpy(record.effect_path,physical);record.before=*before;if(after)record.after=*after;
    return vau_journal_append(p->upload->journal,&record);
}
static int delete_visit(void *opaque,const char *physical,const struct vau_file_info *info)
{
    struct purge_context *p=opaque;char path[VAU_PATH_MAX];int rc=logical(p,physical,path);if(rc)return rc;
    if(vau_policy_evaluate(p->upload->policy,p->request->subject,VAU_FS_PURGE,path,(int)p->request->yes)!=VAU_POLICY_ALLOW)return VAU_DENIED;
    int directory=info->kind==VAU_FILE_DIRECTORY;
    struct vau_write_observation before={0},after={0};
    rc=vau_write_observe(physical,&before);if(rc)return rc;
    rc=event(p,directory ? "purge_dir_intent":"purge_file_intent",path,physical,VAU_BUSY,&before,NULL);if(rc)return rc;
    if(p->upload->stopped(p->upload->context))return VAU_DENIED;
    struct vau_file_info current;rc=vau_vita_file_stat(NULL,physical,&current);if(rc)return rc;
    if(current.kind!=info->kind)return VAU_STALE;
    *p->started=1;
    rc=directory ? sceIoRmdir(physical):sceIoRemove(physical);
    if(rc<0){(void)vau_write_observe(physical,&after);(void)event(p,"purge_native_failed",path,physical,rc,&before,&after);return VAU_RECOVERY_REQUIRED;}
    char mount[9]={0};const char *colon=strchr(physical,':');memcpy(mount,physical,(size_t)(colon-physical)+1);
    rc=sceIoSync(mount,0);if(rc<0)return VAU_RECOVERY_REQUIRED;
    rc=vau_write_observe(physical,&after);
    if(rc || after.state!=VAU_STATE_MISSING){(void)event(p,"purge_after_uncertain",path,physical,VAU_RECOVERY_REQUIRED,&before,&after);return VAU_RECOVERY_REQUIRED;}
    rc=event(p,directory ? "purge_dir_done":"purge_file_done",path,physical,VAU_OK,&before,&after);
    return rc ? VAU_RECOVERY_REQUIRED:VAU_OK;
}
static int apply(void *opaque,const struct vau_write_request *r,unsigned *started,unsigned *readback)
{
    struct purge_context *p=opaque;*started=0;*readback=0;p->started=started;
    int rc=provenance(p,r);if(rc)return rc;
    rc=vau_native_tree_walk(p->physical,1,delete_visit,p,p->upload->stopped,p->upload->context);
    return rc && *started ? VAU_RECOVERY_REQUIRED:rc;
}
static int lookup(void *opaque,const char *subject,const char *id,struct vau_write_record *out)
{struct purge_context *p=opaque;return vau_journal_lookup(p->upload->journal,subject,id,out);}
static int audit(void *opaque,struct vau_write_record *record)
{
    struct purge_context *p=opaque;record->observed_us=p->upload->clock(p->upload->context);
    if(record->phase==VAU_WRITE_INTENT) {
        int rc=provenance(p,&record->request);if(rc)return rc;
        strcpy(record->effect_path,p->physical);rc=vau_write_observe(p->physical,&record->before);if(rc)return rc;
    } else if(record->phase==VAU_WRITE_COMPLETE)(void)vau_write_observe(record->effect_path,&record->after);
    return vau_journal_append(p->upload->journal,record);
}
static int stopped(void *opaque)
{struct purge_context *p=opaque;return p->upload->stopped(p->upload->context);}
int vau_trash_purge(struct vau_upload_context *upload,const struct vau_write_request *r,struct vau_write_record *out)
{
    if(!upload || !upload->policy || !upload->journal || !upload->clock || !upload->stopped || !r || r->operation!=VAU_FS_PURGE)return VAU_INVALID;
    struct purge_context context={.upload=upload};
    struct vau_write_adapter adapter={.context=&context,.lookup=lookup,.audit=audit,.preflight=preflight,.apply=apply,.stopped=stopped};
    return vau_write_execute(upload->policy,&adapter,r,out);
}
