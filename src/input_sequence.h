/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_INPUT_SEQUENCE_H
#define VAU_INPUT_SEQUENCE_H

#include "protocol.h"

/* Compile bounded readable state changes or legacy array events into one
 * complete pad/touch state per distinct timestamp, staged through the
 * command's stream. No heap allocation. */
int vau_input_events_parse(const char *, const struct vau_json_token *, size_t,
                           struct vau_command *);

/* A NULL stage callback makes any staging attempt fail as unsupported. */
void vau_input_stream_init(struct vau_input_stream *, void *context,
                           int (*stage)(void *, uint32_t, uint32_t, uint32_t, const void *));

/* Writes entry index of kind: either the next one, or the newest again. */
int vau_input_stream_put(struct vau_input_stream *, uint32_t kind, uint32_t index,
                         const void *entry);

/* Stages what is left and digests everything staged, per kind. The staged
 * count of a kind is then its base. */
int vau_input_stream_finish(struct vau_input_stream *, unsigned char digests[2][32]);

#endif
