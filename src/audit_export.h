/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_AUDIT_EXPORT_H
#define VAU_AUDIT_EXPORT_H

#include "write_journal.h"

#define VAU_AUDIT_EXPORT_BYTES 16384u

/* Returns encoded bytes or a negative error. Cursor is exclusive and all
 * integer identities/timestamps are decimal strings to preserve precision. */
int vau_audit_export(struct vau_write_journal *, uint64_t, char *, size_t);
int vau_vita_audit_export(void *, uint64_t, char *, size_t);

#endif
