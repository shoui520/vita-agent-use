/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_EVENTS_H
#define VAU_EVENTS_H
#include "vita_agent.h"
#define VAU_DUMP_PATH_BYTES 256u
#define VAU_EVENT_RING_COUNT 16u
#define VAU_EVENT_PAGE_COUNT 2u
enum { VAU_DUMP_SAVING=1,VAU_DUMP_COMPLETE=2 };
typedef struct {
    uint64_t observed_us;
    uint32_t sequence,kind;
    char path[VAU_DUMP_PATH_BYTES];
} VauDumpEvent;
typedef struct {
    uint32_t size,abi,next,latest,count,more,lost,dropped;
    VauDumpEvent events[VAU_EVENT_PAGE_COUNT];
} VauDumpPage;
int vauDumpEvents(uint32_t operation,uint32_t after,VauDumpPage *out);
int vau_dump_events_kernel(uint32_t operation,uint32_t after,VauDumpPage *out);
#endif
