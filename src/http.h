/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_HTTP_H
#define VAU_HTTP_H

#include <stddef.h>
#include "protocol.h"

#define VAU_HTTP_HEADER_BYTES     2048u
#define VAU_TOKEN_HEX_BYTES       64u
#define VAU_PAIRING_REQUEST_BYTES 1024u

enum vau_http_state {
	VAU_HTTP_MORE,
	VAU_HTTP_READY,
	VAU_HTTP_ERROR
};

struct vau_http_request {
	size_t used, header_bytes, body_bytes;
	enum vau_http_state state;
	unsigned error_status;
	unsigned close_connection;
	unsigned frame_request;
	unsigned file_read_request;
	unsigned audit_request;
	unsigned upload_request;
	unsigned pairing_only;
	char token[VAU_TOKEN_HEX_BYTES + 1];
	char data[VAU_HTTP_HEADER_BYTES + VAU_REQUEST_BYTES + 1];
};

void vau_http_init(struct vau_http_request *request);

/* Local bootstrap owner only, after quarantined TLS proves peer possession.
 * Accepts only POST /v1/pair without Authorization. Never command-dispatchable.
 * One request per connection; owner closes after the pairing result. */
void vau_http_init_pairing(struct vau_http_request *request);

/* Saved-peer TLS owner only: POST /v1/session; cannot accept /v1/pair. */
void vau_http_init_session(struct vau_http_request *request);

/* Quarantined admission: accepts pair or session, never commands. Owner must
 * check the exact saved certificate before granting an automatic session. */
void vau_http_init_admission(struct vau_http_request *request);

/* One POST /v1/command, /v1/frame, /v1/file/read, /v1/file/upload or /v1/audit
 * at a time. No chunking or pipelining. After sending the complete response,
 * the transport may reinitialize this parser for the next request on the same
 * authenticated connection. Honor close_connection and close on framing errors.
 *
 * Parsing does NOT authenticate the bearer token. Authenticate EVERY request,
 * including those on reused TLS: the transport must verify the token against a
 * live on-device session over a protected channel before dispatching JSON. */
enum vau_http_state vau_http_feed(struct vau_http_request *request, const void *data, size_t size);

/* EOF before READY is a truncated request, never dispatchable. */
enum vau_http_state vau_http_eof(struct vau_http_request *request);
int vau_http_response_header(char *out, size_t capacity, unsigned status, size_t body_bytes);
int vau_http_response_header_ex(char *out, size_t capacity, unsigned status, size_t body_bytes,
                                unsigned keep_alive);
int vau_http_audit_response_header(char *, size_t, unsigned, size_t, unsigned);

#endif
