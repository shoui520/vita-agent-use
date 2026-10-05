/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_UPLOAD_WIRE_H
#define VAU_UPLOAD_WIRE_H

#include "staged_upload.h"

#define VAU_UPLOAD_METADATA_BYTES 3072u

enum vau_upload_action {
	VAU_UPLOAD_BEGIN,
	VAU_UPLOAD_CHUNK,
	VAU_UPLOAD_VERIFY,
	VAU_UPLOAD_COMMIT,
	VAU_UPLOAD_RECOVER
};

struct vau_upload_message {
	struct vau_write_request request;
	enum vau_upload_action action;
	uint64_t offset;
	const unsigned char *data;
	uint32_t data_bytes;
};

/* Body = big-endian uint32 JSON length + metadata JSON + raw chunk bytes.
 * The authenticated session supplies subject; metadata cannot specify it. */
int vau_upload_wire_parse(const void *, size_t, const char *, struct vau_upload_message *);
int vau_upload_wire_reply(const struct vau_upload_message *, int, const struct vau_upload_status *,
                          const struct vau_write_record *, char *, size_t);

#endif
