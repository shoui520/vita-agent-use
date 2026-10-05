/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_CONFIG_NATIVE_H
#define VAU_CONFIG_NATIVE_H

#include "staged_upload.h"

/* Internal paths are derived from a bound write request, never accepted as
 * recovery paths from the peer. Both configs must match the request digests. */
int vau_config_native_check(struct vau_upload_context *, const struct vau_write_request *,
                            const char *before_path, const char *after_path);
int vau_config_native_preflight(struct vau_upload_context *, const struct vau_write_request *,
                                const char *);
int vau_config_recovery_copy_check(struct vau_upload_context *);

#endif
