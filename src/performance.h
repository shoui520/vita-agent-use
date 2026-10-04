/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_PERFORMANCE_H_CORE
#define VAU_PERFORMANCE_H_CORE
#include "vau_performance.h"
#include <stddef.h>
#define VAU_PERF_SAMPLES 64u
struct vau_perf_observation {
    uint64_t time_us,idle[4];
    int cpu_error;
    VauPerformanceRaw raw;
};
struct vau_perf_sample {
    uint64_t begin_us,end_us;
    uint32_t index,cpu_bp[4],fps_milli;
    int cpu_error,fps_error;
    VauPerformanceRaw raw;
};
struct vau_perf_watch {
    uint64_t owner,generation,start_us,next_us;
    uint32_t interval_us,duration_us,count;
    int active;
    struct vau_perf_observation previous;
    struct vau_perf_sample samples[VAU_PERF_SAMPLES];
};
int vau_perf_start(struct vau_perf_watch *,uint64_t owner,uint32_t interval_ms,uint32_t duration_ms,
    const struct vau_perf_observation *);
int vau_perf_tick(struct vau_perf_watch *,const struct vau_perf_observation *);
int vau_perf_json(const struct vau_perf_watch *,uint64_t owner,uint32_t after,char *,size_t);
void vau_performance_stop(void);
int vau_vita_performance(void *,uint64_t owner,unsigned op,uint32_t value,uint32_t after,char *,size_t);
#endif
