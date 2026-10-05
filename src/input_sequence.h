/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_INPUT_SEQUENCE_H
#define VAU_INPUT_SEQUENCE_H

#include "protocol.h"

/* Compile bounded readable state changes or legacy array events into one
 * complete pad/touch state per distinct timestamp. No heap allocation. */
int vau_input_events_parse(const char *, const struct vau_json_token *, size_t,
                           struct vau_command *);

#endif
