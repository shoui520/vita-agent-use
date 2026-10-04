/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "content_sdk.h"
#include "native_ops.h"
#include <string.h>
void vau_content_sdk_init(struct vau_content_sdk *s,const struct vau_content_sdk_loader *loader)
{memset(s,0,sizeof(*s));if(loader)s->loader=*loader;}
static int bind(struct vau_content_sdk *s)
{
    if(s->bound)return VAU_OK;
    if(!s->loader.loaded || !s->loader.load || !s->loader.resolve)return VAU_INVALID;
    int rc=s->loader.loaded(s->loader.context);
    /* Only the adapter's explicit UNLOADED result permits loading. */
    if(rc==1)rc=s->loader.load(s->loader.context);
    if(rc)return rc;
    const uint32_t nids[]={0x93451536,0xabec74d2,0x7d46752f};
    uintptr_t addresses[3]={0};
    for(unsigned i=0;i<3;i++) {
        rc=s->loader.resolve(s->loader.context,nids[i],&addresses[i]);
        if(rc)return rc;
        if(!addresses[i])return VAU_DEVICE_ERROR;
    }
    /* No partially resolved callback is published on an error. */
    s->initialize=(int (*)(void))addresses[0];
    s->state=(int (*)(int *))addresses[1];
    s->delete_package=(int (*)(const char *))addresses[2];
    s->bound=1;return VAU_OK;
}
static int prepare(struct vau_content_sdk *s)
{
    int rc=bind(s);if(rc)return rc;
    int state=-1;rc=s->state(&state);if(rc)return rc;
    if(state!=0)return VAU_BUSY;
    if(!s->initialized) {
        rc=s->initialize();if(rc)return rc;
        s->initialized=1;
        state=-1;rc=s->state(&state);if(rc)return rc;
        if(state!=0)return VAU_BUSY;
    }
    return VAU_OK;
}
int vau_content_sdk_delete(void *context,const char *title)
{
    struct vau_content_sdk *s=context;
    if(!s || !vau_title_valid(title) || !strncmp(title,"NPXS",4))return VAU_INVALID;
    int rc=prepare(s);if(rc)return rc;
    /* 3.65 DeletePkg owns its 200 ms polling until native completion.
     * Never kill the worker on timeout. No manual registry/filesystem deletes. */
    return s->delete_package(title);
}
int vau_content_sdk_promote(struct vau_content_sdk *s,const char *path)
{
    if(!s || !path || !path[0])return VAU_INVALID;
    int rc=prepare(s);if(rc)return rc;
    if(!s->promote_package) {
        uintptr_t address=0;
        rc=s->loader.resolve(s->loader.context,UINT32_C(0x86641bc6),&address);
        if(rc)return rc;
        if(!address)return VAU_DEVICE_ERROR;
        s->promote_package=(int (*)(const char *,int))address;
    }
    return s->promote_package(path,1); /* Sony owns synchronous completion. */
}
int vau_content_sdk_remove_savedata(struct vau_content_sdk *s,const char *title,unsigned user)
{
    if(!s || !vau_title_valid(title) || !strncmp(title,"NPXS",4) || user>=64)return VAU_INVALID;
    int rc=bind(s);if(rc)return rc;
    if(!s->remove_savedata) {
        uintptr_t address=0;
        rc=s->loader.resolve(s->loader.context,UINT32_C(0xcb0a59b0),&address);
        if(rc)return rc;
        if(!address)return VAU_DEVICE_ERROR;
        s->remove_savedata=(int (*)(const char *,int,int))address;
    }
    rc=prepare(s);if(rc)return rc;
    /* Actual 3.65: external mode 1 selects internal mode 4 and the third
     * argument selects one numbered user. Modes 2/3 select current/all users;
     * never substitute either for a specified-user operation. The official
     * export owns its completion polling; run only on the SDK worker. */
    return s->remove_savedata(title,1,(int)user);
}
