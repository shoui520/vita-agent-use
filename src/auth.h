/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_AUTH_H
#define VAU_AUTH_H

#include "http.h"

#define VAU_AUTH_SLOTS           4u
#define VAU_AUTH_TOKEN_BYTES     32u
#define VAU_AUTH_MAX_LIFETIME_US UINT64_C(86400000000)

struct vau_auth_entry {
	uint64_t handle, expires_us;
	unsigned char token[VAU_AUTH_TOKEN_BYTES];
	struct vau_session session;
};

struct vau_auth {
	uint64_t next_handle;

	uint64_t stop_generation;
	int stopped;
	struct vau_auth_entry entries[VAU_AUTH_SLOTS];
};

/* Caller serializes the registry and protocol execution with the same lock.
 * Entropy provider must fill the entire buffer from a cryptographic source,
 * returning zero on success. It is never supplied by a network request. */
typedef int (*vau_entropy)(void *context, void *output, size_t size);
int vau_vita_entropy(void *context, void *output, size_t size);
void vau_auth_init(struct vau_auth *auth);

/* TRUSTED LOCAL PATH ONLY: eventual pairing UI approves this grant. No remote
 * route may call this merely because a request asks for a permission flag.
 * Token must be delivered over a protected channel and never logged. */
int vau_auth_grant(struct vau_auth *auth, unsigned rights, uint64_t now_us, uint64_t lifetime_us,
                   vau_entropy entropy, void *context, uint64_t *handle,
                   char token[VAU_TOKEN_HEX_BYTES + 1]);
int vau_auth_revoke(struct vau_auth *auth, uint64_t handle);
void vau_auth_revoke_all(struct vau_auth *auth);

/* Trusted local stop/rearm, serialized with request execution. Stop revokes
 * every grant and prevents new grants, including automatic trusted-peer
 * reconnects. Rearm requires a fresh local decision for the current generation;
 * it does not restore any token. No remote operation exposes these functions.
 * Input cancellation is separately required in the kernel scheduler. */
void vau_auth_stop(struct vau_auth *auth);
int vau_auth_rearm(struct vau_auth *auth, uint64_t generation);
struct vau_session *vau_auth_lookup(struct vau_auth *auth, const char *token, size_t token_length,
                                    uint64_t now_us);

/* Dispatch a completely framed request only after finding a live Vita-side
 * grant. Caller must already have established protected transport. */
int vau_authenticated_request(struct vau_auth *auth, const struct vau_native_api *api,
                              const struct vau_http_request *request, char *response,
                              size_t capacity, unsigned *http_status);

#endif
