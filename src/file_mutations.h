/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_FILE_MUTATIONS_H
#define VAU_FILE_MUTATIONS_H

#include "staged_upload.h"

int vau_mutation_trash_path(const struct vau_write_request *, char[VAU_PATH_MAX]);
int vau_mutation_execute(struct vau_upload_context *, const struct vau_write_request *,
                         struct vau_write_record *);
int vau_trash_purge(struct vau_upload_context *, const struct vau_write_request *,
                    struct vau_write_record *);
int vau_write_observe(const char *, struct vau_write_observation *);

#endif
