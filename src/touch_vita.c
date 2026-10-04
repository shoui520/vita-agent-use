/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "native_ops.h"
#include "touch_sample.h"
#include <psp2/touch.h>
#include <stddef.h>
#include <string.h>
_Static_assert(sizeof(SceTouchData)==sizeof(struct vau_touch_frame),"Native touch frame size");
_Static_assert(sizeof(SceTouchReport)==sizeof(struct vau_touch_report),"Native touch report size");
_Static_assert(offsetof(SceTouchData,report)==offsetof(struct vau_touch_frame,reports),"Native touch reports offset");
_Static_assert(offsetof(SceTouchReport,info)==offsetof(struct vau_touch_report,info),"Native touch info offset");
int vau_vita_touch_panel(void *context,unsigned port,struct vau_touch_panel *out)
{
    (void)context;
    if (!out) return VAU_INVALID;
    memset(out,0,sizeof(*out));
    if (port>=SCE_TOUCH_PORT_MAX_NUM) return VAU_INVALID;
    _Static_assert(sizeof(SceTouchPanelInfo)==0x30,"Touch panel ABI");
    SceTouchPanelInfo native={0};
    int rc=sceTouchGetPanelInfo(port,&native);
    if (rc<0) return rc;
    if (native.minAaX>=native.maxAaX || native.minAaY>=native.maxAaY ||
        native.minDispX>=native.maxDispX || native.minDispY>=native.maxDispY ||
        native.minForce>native.maxForce) return VAU_DEVICE_ERROR;
    *out=(struct vau_touch_panel){native.minAaX,native.minAaY,native.maxAaX,native.maxAaY,
        native.minDispX,native.minDispY,native.maxDispX,native.maxDispY,native.minForce,native.maxForce};
    return VAU_OK;
}
