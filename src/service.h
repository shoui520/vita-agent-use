/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_SERVICE_H
#define VAU_SERVICE_H

#include "auth.h"
#include "input_owner.h"

struct vau_stop_bridge {
	void *context;

	int (*status)(void *context, VauStopStatus *status);
	int (*rearm)(void *context, uint64_t generation);
};
extern const struct vau_stop_bridge vau_vita_stop_bridge;

struct vau_service {
	struct vau_auth auth;
	struct vau_input_owner input;
	VauStopStatus stop;
	struct vau_stop_bridge bridge;
	int observed, valid, fault;
	void *activity_context;

	void (*activity)(void *, uint64_t, const char *, uint64_t);

	void *stop_notice_context;

	int (*stop_notice)(void *); /* Local informational UI; never rearms control. */
	unsigned stop_notice_pending;
	int approval_pending; /* Native local approval inhibits all injected input. */
};

/* Shell owns serialization of poll, grant, rearm and dispatch. Also poll from
 * its worker while idle, and between steps of long operations. A native call
 * already in flight cannot be undone by this gate. */
void vau_service_init(struct vau_service *s, const struct vau_stop_bridge *bridge);
int vau_service_poll(struct vau_service *s);

/* Authentication transport survives temporary sampling unavailability.
 * Dispatch/input still require full readiness. Physical stops revoke grants. */
int vau_service_transport_poll(struct vau_service *s);

/* Initialize once before serving requests, while stopped and with no input owner. */
int vau_service_attach_input(struct vau_service *s, const struct vau_input_bridge *bridge);

/* Local UI only: capture both generations for the displayed approval, then
 * pass those exact values on confirmation. No remotely supplied bypass. */
int vau_service_rearm(struct vau_service *s, uint64_t local_generation, uint64_t kernel_generation);
int vau_service_grant(struct vau_service *s, unsigned rights, uint64_t now, uint64_t lifetime,
                      vau_entropy entropy, void *context, uint64_t *handle,
                      char token[VAU_TOKEN_HEX_BYTES + 1]);
int vau_service_request(struct vau_service *s, const struct vau_native_api *api,
                        const struct vau_http_request *request, char *response, size_t capacity,
                        unsigned *http_status);

#endif
