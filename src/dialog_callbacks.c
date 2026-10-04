/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "dialog_callbacks.h"
#include <stddef.h>
#include <string.h>
extern void *vauPafMalloc(size_t size);
extern void vauPafFree(void *pointer);

struct vau_dialog_callback {
    const void *vtable;
    struct vau_dialog_callback_hooks hooks;
    void *context;
    enum vau_dialog_callback_kind kind;
    unsigned destroyed;
};
_Static_assert(offsetof(struct vau_dialog_callback,vtable)==0,"Native callback vptr");
#if defined(__arm__)
_Static_assert(sizeof(void *)==4,"Native callback pointer ABI");
_Static_assert(offsetof(struct vau_dialog_result_vtable,event)==8,"Native result slot");
_Static_assert(offsetof(struct vau_dialog_lifecycle_vtable,event)==8,"Native lifecycle slot");
#endif
static void destroy(struct vau_dialog_callback *self)
{
    if (self->destroyed) return;
    self->destroyed=1;
    void (*released)(void *,enum vau_dialog_callback_kind)=self->hooks.released;
    void *context=self->context;
    self->context=NULL;
    memset(&self->hooks,0,sizeof(self->hooks));
    released(context,self->kind);
}
static void delete_object(struct vau_dialog_callback *self)
{
    destroy(self);
    vauPafFree(self);
}
static void result_event(struct vau_dialog_callback *self,int32_t id,int32_t result)
{
    if (!self->destroyed) self->hooks.result(self->context,id,result);
    /* A hook can trigger native cleanup. Do not touch self after the call. */
}
static void lifecycle_event(struct vau_dialog_callback *self)
{
    if (!self->destroyed) self->hooks.lifecycle(self->context);
}
static const struct vau_dialog_result_vtable result_vtable={destroy,delete_object,result_event};
static const struct vau_dialog_lifecycle_vtable lifecycle_vtable={destroy,delete_object,lifecycle_event};
void vau_dialog_callbacks_discard(struct vau_dialog_callback_pair *owned)
{
    if (!owned) return;
    struct vau_dialog_callback_pair pair=*owned;
    memset(owned,0,sizeof(*owned));
    if (pair.result) delete_object(pair.result);
    if (pair.lifecycle) delete_object(pair.lifecycle);
}
int vau_dialog_callbacks_create(struct vau_dialog_callback_pair *out,
    const struct vau_dialog_callback_hooks *hooks,void *context)
{
    if (!out || !hooks || !hooks->result || !hooks->lifecycle || !hooks->released)
        return VAU_INVALID;
    /* Reusing a populated output would lose native-owned storage. */
    if (out->result || out->lifecycle) return VAU_BUSY;
    struct vau_dialog_callback *result=vauPafMalloc(sizeof(*result));
    if (!result) return VAU_DEVICE_ERROR;
    struct vau_dialog_callback *lifecycle=vauPafMalloc(sizeof(*lifecycle));
    if (!lifecycle) {
        vauPafFree(result);
        return VAU_DEVICE_ERROR;
    }
    *result=(struct vau_dialog_callback){&result_vtable,*hooks,context,VAU_DIALOG_RESULT,0};
    *lifecycle=(struct vau_dialog_callback){&lifecycle_vtable,*hooks,context,VAU_DIALOG_LIFECYCLE,0};
    out->result=result; out->lifecycle=lifecycle;
    return VAU_OK;
}
