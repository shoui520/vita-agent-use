/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_PACKAGE_INSTALL_H
#define VAU_PACKAGE_INSTALL_H

#include <stddef.h>
#include <stdint.h>

struct vau_service;

/* Initialization performs no I/O or sysmodule loading at Shell boot. */
void vau_vita_install_init(struct vau_service *);
void vau_vita_install_poll(void);
int vau_vita_install_busy(void);
int vau_vita_install(void *, uint64_t, const char *, const char *, const char *, int, char *,
                     size_t);

#endif
