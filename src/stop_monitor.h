/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_STOP_MONITOR_H
#define VAU_STOP_MONITOR_H
#include "vita_agent.h"
#define VAU_STOP_CHORD 0x00010001u
#define VAU_STOP_POLL_US 16000u
#define VAU_STOP_STALE_US 250000u
struct vau_stop_monitor {
    uint64_t stamp, changed_us, read_us;
    int error, sampled, held, fault;
    uint64_t raw_stamp, previous_stamp, observed_us;
    int result;
    uint32_t mask, buttons, reason;
};
/* Returns one only for a new chord. Observation failures clear readiness;
 * callers release input without recording a user stop. OS samples may include
 * other plugins' emulation. */
int vau_stop_observe(struct vau_stop_monitor *m, int result, uint32_t mask,
                     uint32_t buttons, uint64_t stamp, uint64_t now);
int vau_stop_ready(const struct vau_stop_monitor *m, uint64_t now);
#endif
