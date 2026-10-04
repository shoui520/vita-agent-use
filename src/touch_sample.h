/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_TOUCH_SAMPLE_H
#define VAU_TOUCH_SAMPLE_H
#include "native_ops.h"
#define VAU_TOUCH_FRONT_CONTACTS 6u
#define VAU_TOUCH_BACK_CONTACTS 4u
#define VAU_TOUCH_REFRESH_US UINT64_C(32000)
struct vau_touch_pose {
    uint64_t changed_us,refreshed_us,until_us;
    int32_t process; /* Zero: physical-style native routing; positive: macro target. */
    uint8_t enabled,count[2],reserved;
    struct vau_touch_contact contacts[2][VAU_TOUCH_FRONT_CONTACTS];
};
/* Native SceTouchData layout. Keep timestamp/status, replace only reports for
 * explicitly owned panels before native routing/region/read filtering. */
struct vau_touch_report {
    uint8_t id,force;
    int16_t x,y;
    uint8_t reserved[8];
    uint16_t info;
};
struct vau_touch_frame {
    uint64_t timestamp;
    uint32_t status,count;
    struct vau_touch_report reports[8];
};
int vau_touch_pose_validate(const struct vau_touch_pose *pose,const struct vau_touch_panel panels[2]);
/* Resolve the native owner of a coordinate, under the caller's native routing
 * serialization. Return a positive PID or a negative error/no-owner result.
 * Controller routing alone does not establish touch ownership. */
typedef int32_t (*vau_touch_owner)(void *context,unsigned port,int16_t x,int16_t y);
/* Immutable validated pose, no allocations or internal locks. Ordinary input
 * uses process=0 and enters the native routing/region filtering after decode,
 * just like physical contacts. Macro poses require matching controller routing
 * and coordinate ownership. Freshness and explicitly owned panel limits apply
 * in both modes. Return modified panel bits, not app observation confirmation. */
unsigned vau_touch_override(const struct vau_touch_pose *pose,uint64_t now,int32_t process,
    struct vau_touch_frame *front,struct vau_touch_frame *back,
    vau_touch_owner owner,void *context);
#endif
