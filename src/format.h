/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_FORMAT_H
#define VAU_FORMAT_H

/* User-mode Vita responses use the OS formatter. The small libk formatter
 * does not honor AAPCS eight-byte variadic alignment for long long values.
 * Host builds retain libc; no formatter is called by the kernel worker. */
#ifdef VAU_NATIVE_FORMAT
#include <psp2/kernel/clib.h>

#define vau_snprintf  sceClibSnprintf
#define vau_vsnprintf sceClibVsnprintf
#else
#include <stdio.h>

#define vau_snprintf  snprintf
#define vau_vsnprintf vsnprintf
#endif
#endif
