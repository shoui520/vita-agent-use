/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_MODULES_H
#define VAU_MODULES_H
#include <stdint.h>
typedef struct VauPluginState {
    uint32_t size,abi,loaded,native_state;
    int32_t module_id;
    char module_name[28];
} VauPluginState;
/* Read-only native module observation, authorized for Shell. */
int vauPluginState(int32_t process,const char path[256],VauPluginState *state);
int vau_modules_kernel_state(int32_t process,const char path[256],VauPluginState *state);
#endif
