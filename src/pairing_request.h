/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_PAIRING_REQUEST_H
#define VAU_PAIRING_REQUEST_H

#include "http.h"
#include "notification.h"

struct vau_pairing_request {
	char name[VAU_AGENT_NAME_BYTES + 1];
	size_t name_length;
};

/* Presentation data only: no grants, trust changes, UI jobs or native calls.
 * Require the locally selected pairing parser mode and a complete request.
 * TLS binding and native OK remain the bootstrap owner's responsibilities. */
int vau_pairing_request_decode(const struct vau_http_request *http,
                               struct vau_pairing_request *out);

#endif
