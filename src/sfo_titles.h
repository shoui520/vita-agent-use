/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_SFO_TITLES_H
#define VAU_SFO_TITLES_H

#include "vita_agent.h"
#include <stddef.h>
#include <stdint.h>

#define VAU_SFO_TITLE_BYTES    128u
#define VAU_SFO_METADATA_BYTES 65536u

struct vau_sfo_titles {
	char title[VAU_SFO_TITLE_BYTES];
	char savedata_title[VAU_SFO_TITLE_BYTES];
};

/* Exact, bounded random reads from an already owned read-only source. */
typedef int (*vau_sfo_read_fn)(void *, uint64_t, void *, uint32_t);
int vau_sfo_titles_read(vau_sfo_read_fn, void *, uint64_t, struct vau_sfo_titles *);
int vau_pbp_titles_read(vau_sfo_read_fn, void *, uint64_t, struct vau_sfo_titles *);
int vau_vita_application_titles(const char *, struct vau_sfo_titles *, char[16]);
int vau_vita_savedata_titles(const char *, struct vau_sfo_titles *);

#endif
