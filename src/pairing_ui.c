/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "pairing_ui.h"
#include <string.h>
static void advance(struct vau_pairing_ui *ui)
{
    if (ui->opening || ui->state!=VAU_PAIR_UI_ACTIVE) return;
    if (!ui->closing && ui->dialog_id>=0 &&
        (ui->result_seen || ui->cancelled)) {
        ui->closing=1; /* Close may synchronously invoke callbacks. */
        vau_dialog_close(ui->dialog_id);
    }
    if (ui->released==3) ui->state=VAU_PAIR_UI_DONE;
}
static void on_result(void *context,int32_t id,int32_t result)
{
    struct vau_pairing_ui *ui=context;
    if (ui->state!=VAU_PAIR_UI_ACTIVE) return;
    if (ui->result_seen) {
        /* Multiple decisions are ambiguous, even if both say OK. */
        ui->cancelled=1;
    } else {
        ui->result_seen=1; ui->event_id=id; ui->event_result=result;
    }
    advance(ui);
}
static void on_lifecycle(void *context)
{
    struct vau_pairing_ui *ui=context;
    ui->lifecycle_seen=1;
    advance(ui);
}
static void on_release(void *context,enum vau_dialog_callback_kind kind)
{
    struct vau_pairing_ui *ui=context;
    ui->released|=1u<<kind;
    advance(ui);
}
void vau_pairing_ui_init(struct vau_pairing_ui *ui)
{
    memset(ui,0,sizeof(*ui));
    ui->dialog_id=-1; ui->event_id=-1;
}
int vau_pairing_ui_begin(struct vau_pairing_ui *ui,const struct vau_pairing_binding *binding,
    const char *name,size_t length,uint64_t now)
{
    struct vau_pairing_prompt prompt;
    int rc=vau_pairing_prompt_format(&prompt,name,length,binding ? binding->certificate_sha256 : NULL);
    return rc<0 ? rc : vau_pairing_ui_begin_prompt(ui,binding,&prompt,now);
}
int vau_pairing_ui_begin_prompt(struct vau_pairing_ui *ui,const struct vau_pairing_binding *binding,
    const struct vau_pairing_prompt *prompt,uint64_t now)
{
    if (!ui || !binding || !binding->connection || !prompt || !prompt->length ||
        prompt->length>=VAU_PAIRING_TEXT_UNITS || prompt->text[prompt->length] ||
        now>UINT64_MAX-VAU_PAIRING_UI_TIMEOUT_US) return VAU_INVALID;
    if (ui->state!=VAU_PAIR_UI_IDLE) return VAU_BUSY;
    ui->prompt=*prompt;
    int rc;
    ui->binding=*binding;
    ui->last_us=now; ui->deadline_us=now+VAU_PAIRING_UI_TIMEOUT_US;
    ui->state=VAU_PAIR_UI_ACTIVE; ui->opening=1;
    const struct vau_dialog_callback_hooks hooks={on_result,on_lifecycle,on_release};
    struct vau_dialog_callback_pair callbacks={0};
    rc=vau_dialog_callbacks_create(&callbacks,&hooks,ui);
    if (rc<0) {
        ui->released=3; ui->cancelled=1;
    } else {
        rc=vau_dialog_open(&ui->prompt,&callbacks,&ui->dialog_id);
        /* This only frees pre-Open objects. Open clears the consumed pair. */
        if (callbacks.result || callbacks.lifecycle) vau_dialog_callbacks_discard(&callbacks);
        if (rc<0) ui->cancelled=1;
    }
    ui->open_status=rc;
    ui->opening=0;
    advance(ui);
    return rc;
}
void vau_pairing_ui_cancel(struct vau_pairing_ui *ui)
{
    if (!ui || ui->state==VAU_PAIR_UI_IDLE) return;
    ui->cancelled=1;
    advance(ui);
}
static int same_binding(const struct vau_pairing_binding *a,const struct vau_pairing_binding *b)
{
    return b && a->connection==b->connection &&
        a->local_stop_generation==b->local_stop_generation &&
        a->kernel_stop_generation==b->kernel_stop_generation &&
        !memcmp(a->certificate_sha256,b->certificate_sha256,32);
}
int vau_pairing_ui_poll(struct vau_pairing_ui *ui,const struct vau_pairing_binding *current,
    uint64_t now)
{
    if (!ui || ui->state==VAU_PAIR_UI_IDLE) return VAU_INVALID;
    if (!same_binding(&ui->binding,current) || now<ui->last_us || now>=ui->deadline_us)
        vau_pairing_ui_cancel(ui);
    ui->last_us=now;
    advance(ui);
    if (ui->state!=VAU_PAIR_UI_DONE) return VAU_BUSY;
    return !ui->cancelled && ui->open_status==VAU_OK && ui->result_seen &&
        ui->event_id==ui->dialog_id && ui->event_result==2 ? VAU_OK : VAU_DENIED;
}
int vau_pairing_ui_reset(struct vau_pairing_ui *ui)
{
    if (!ui) return VAU_INVALID;
    if (ui->state!=VAU_PAIR_UI_DONE) return VAU_BUSY;
    vau_pairing_ui_init(ui);
    return VAU_OK;
}
