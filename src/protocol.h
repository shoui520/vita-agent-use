/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_PROTOCOL_H
#define VAU_PROTOCOL_H

#include "native_ops.h"
#include <stddef.h>
#include "json.h"

#define VAU_REQUEST_BYTES  131072u
#define VAU_RESPONSE_BYTES 4096u
#define VAU_COMMAND_TOKENS 128u

enum vau_session_right {
	VAU_RIGHT_OBSERVE = 1u,
	VAU_RIGHT_CONTROL = 2u
};

struct vau_command {
	uint64_t id;
	unsigned operation;
	char title[VAU_TITLE_BYTES];
	char app_after[VAU_APP_ID_BYTES], app_query[VAU_APP_QUERY_BYTES];
	char path[VAU_PATH_MAX];
	char log_marker[129], content_category[32];
	uint32_t offset, start_delay_us, blob_position;
	char blob_page[21], blob_column[11];
	char mutation_id[33], destination[VAU_PATH_MAX];
	char trash_id[33];
	unsigned yes;
	uint64_t content_before, content_after, content_cursor, content_media_id;
	unsigned content_kind, content_user;
	int32_t process;
	VauSequence sequence;
	VauEvent events[VAU_MAX_EVENTS];
	unsigned has_touch, readable_input;
	VauTouchState touch[VAU_MAX_EVENTS];
};

struct vau_session {
	uint64_t handle; /* Set only by the authenticated registry. */
	unsigned rights;
	char agent_name[129]; /* Validated pairing label; presentation only. */
	char subject[65];     /* Paired certificate SHA256; never supplied in JSON. */
	unsigned reboot_pending, reboot_reply;
	unsigned push_enabled, perf_push;
	uint64_t run_started_us;
	uint32_t dump_after, dialog_after, perf_after, dump_dropped, dialog_dropped, log_ids[4];
	char run_id[33], run_title[VAU_TITLE_BYTES], run_phase[24];
	uint64_t last_id;
	unsigned char last_digest[32];
	size_t reply_length;
	char reply[VAU_RESPONSE_BYTES];
};

/* Parsing uses one shared bounded workspace, with a nonblocking guard against
 * concurrent calls. Native callbacks must not recursively dispatch commands. */
/* Session is owned by one authenticated connection/controller. Only trusted
 * on-device authorization may set rights; JSON never supplies them. Caller
 * serializes requests and creates a new session on reauthentication/reboot.
 * One cached response; older IDs are rejected rather than re-executed. */
/* Validated event subscription only; never input or application commands. */
int vau_protocol_background_request(const char *request, size_t length);
void vau_session_init(struct vau_session *session, unsigned rights);

/* Returns response byte count or a negative local error. Capacity must be at
 * least VAU_RESPONSE_BYTES, checked before any native effect. No network or
 * authentication is implemented here; the transport must authenticate first. */
int vau_protocol_request(struct vau_session *session, const struct vau_native_api *api,
                         const char *request, size_t length, char *response, size_t capacity);

#endif
