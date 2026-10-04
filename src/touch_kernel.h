/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_TOUCH_KERNEL_H
#define VAU_TOUCH_KERNEL_H
#include "touch_sample.h"
/* Caller serializes enable/publish/clear through the input service guard.
 * enable is explicit, never called by module_start. A successful installation
 * stays resident until reboot, matching the kernel module's lifetime. */
int vau_touch_kernel_enable(void);
int vau_touch_kernel_panel(unsigned port,struct vau_touch_panel *out);
int vau_touch_kernel_publish(const struct vau_touch_pose *pose,const struct vau_touch_panel panels[2]);
void vau_touch_kernel_clear(void);
#endif
