/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_TAI_CONFIG_GUARD_H
#define VAU_TAI_CONFIG_GUARD_H

#include <stddef.h>

#define VAU_TAI_CONFIG_BYTES 16384u

/* Recovery flags come from the trusted native adapter, never agent JSON.
 * This comparison preserves critical lines and their effective loading under
 * taiHEN's ALL/KERNEL/title and ! halt semantics. It does not verify that
 * non-critical plugin binaries exist or work. The native adapter separately
 * validates request digests and the recovery copy. */
int vau_tai_config_check(const void *before, size_t before_bytes, const void *after,
                         size_t after_bytes, int storage_requires_recovery, int recovery_valid);

#endif
