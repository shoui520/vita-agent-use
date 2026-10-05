/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_ACL_APPROVAL_H
#define VAU_ACL_APPROVAL_H

#include "pairing_ui.h"
#include "ui_vita.h"
#include "service.h"

struct vau_acl_approval {
	struct vau_ui_job job;
	struct vau_pairing_ui ui;
	struct vau_pairing_prompt prompt;
	struct vau_pairing_binding binding;
	struct vau_service *service;
	const struct vau_native_api *api;
	atomic_uint cancelled;
	uint64_t handle, deadline;
	int active, begin_job, ui_finished, result;
};

void vau_acl_approval_init(struct vau_acl_approval *, struct vau_service *,
                           const struct vau_native_api *);
int vau_acl_approval_begin(struct vau_acl_approval *, uint64_t, const char *,
                           const struct vau_pairing_prompt *);
int vau_acl_approval_poll(struct vau_acl_approval *);
void vau_acl_approval_cancel(struct vau_acl_approval *);

/* Called after persistence/result handling. Does not rearm physical stop. */
int vau_acl_approval_finish(struct vau_acl_approval *);

#endif
