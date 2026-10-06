/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_PEER_STORE_H
#define VAU_PEER_STORE_H

#include <stddef.h>

/* Match returns 1 for an exact approved certificate, 0 for absent, or an error.
 * Storage is one file per identity; memory and lookup cost do not grow with peers. */
const char *vau_peer_store_stage(void);
int vau_peer_match(const unsigned char *certificate, size_t size);
int vau_peer_save(const unsigned char *certificate, size_t size);

#endif
