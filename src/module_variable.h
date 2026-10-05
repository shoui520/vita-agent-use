/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_MODULE_VARIABLE_H
#define VAU_MODULE_VARIABLE_H

#include <stddef.h>
#include <stdint.h>

/* Internal read-only Vita export-table lookup. The caller holds the module and
 * supplies a checked memory reader. Normal variables follow function exports;
 * TLS exports are not searched. No peer-supplied module addresses are exposed. */
typedef int (*vau_memory_read)(void *, uintptr_t, void *, size_t);
int vau_module_variable(void *, vau_memory_read, uintptr_t, uintptr_t, uint32_t, uint32_t,
                        uintptr_t *);

#endif
