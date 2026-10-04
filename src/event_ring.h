/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_EVENT_RING_H
#define VAU_EVENT_RING_H
#include "vau_events.h"
struct vau_event_ring { uint32_t latest,count; VauDumpEvent events[VAU_EVENT_RING_COUNT]; };
int vau_dump_path(const char *path,unsigned kind);
int vau_event_publish(struct vau_event_ring *ring,unsigned kind,const char *path,uint64_t now);
int vau_event_read(const struct vau_event_ring *ring,uint32_t after,VauDumpPage *out);
#endif
