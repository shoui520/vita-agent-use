/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CONTENT_MEDIA_CAPTURE_VITA_H
#define VAU_CONTENT_MEDIA_CAPTURE_VITA_H

#include "content_capture.h"

struct vau_media_capture_vita {
	struct vau_media_source source;
	struct vau_media_session_vita paths;
	unsigned initialized, busy, source_cleanup, path_cleanup;
};

/* Fresh owner only. No native loads, mounts, DB opens or allocation at init. */
void vau_vita_media_capture_init(struct vau_media_capture_vita *, void *, int (*)(void *));

/* Read-only capture into an already owned scope. Cleanup precedes success;
 * caller commits only on success and aborts on failure. No delete/approval.
 * Failed cleanup blocks new capture and preserves resources for retry. */
int vau_vita_media_capture(struct vau_media_capture_vita *, struct vau_content_scope_writer *,
                           const struct vau_file_policy *, uint64_t,
                           const struct vau_content_capture_adapter *);
int vau_vita_media_capture_cleanup(struct vau_media_capture_vita *);

#endif
