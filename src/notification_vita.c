/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "notification.h"
#include "vita_agent.h"
#include <stdatomic.h>
#include <string.h>
_Static_assert(sizeof(struct vau_notification_begin)==0x570,"3.65 ProgressBegin ABI");
_Static_assert(offsetof(struct vau_notification_begin,callback)==0x4e8,"Native callback offset");
_Static_assert(offsetof(struct vau_notification_begin,userdata)==0x4ec,"Native callback userdata offset");
_Static_assert(offsetof(struct vau_notification_begin,detail)==0x4f0,"Native third text offset");
static atomic_int styled_result=ATOMIC_VAR_INIT(VAU_STALE);
int vau_vita_notification_style_result(void){return atomic_load(&styled_result);}
/* These exported 3.65 NIDs are supplied by native365.yml. The SDK's payload
 * comment is too small; use the verified complete packet instead. */
extern void *vauShellSvcClient(void);
extern int vauNotificationFinish(const struct vau_styled_notification *packet);
extern int vauNotificationBegin(const struct vau_notification_begin *packet);
extern int vauNotificationSend(const struct vau_notification *packet);
/* NotificationUtil retains this code pointer until Finish unregisters channel
 * 0x34. Plugin code is resident for the lifetime of Shell, even after stop. */
static void progress_event(void) {}
int vau_vita_notification_using(const char *name,size_t length)
{
    struct vau_styled_notification styled;
    int rc=vau_notification_using_styled(&styled,name,length);if(rc<0)return rc;
    if(!vauShellSvcClient())return VAU_UNSUPPORTED;
    struct vau_notification_begin begin;
    memset(&begin,0,sizeof(begin));begin.message=styled;
    begin.callback=(uint32_t)(uintptr_t)progress_event;
    rc=vauNotificationBegin(&begin);
    if(rc>=0)rc=vauNotificationFinish(&styled);
    atomic_store(&styled_result,rc);
    if(rc>=0)return rc;
    /* Preserve the stop instruction if a firmware rejects a standalone finish. */
    struct vau_notification packet;
    rc=vau_notification_using(&packet,name,length);if(rc<0)return rc;
    return vauNotificationSend(&packet);
}
