/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_DIAGNOSTICS_VITA_H
#define VAU_DIAGNOSTICS_VITA_H

/* Hardware-test diagnostics only: fixed status/input/log requests over LAN UDP 8846.
 * No identifiers, credentials, file access, approval or commands. Idle worker
 * blocks on receive; replies limited to one per second. Code stays resident. */
int vau_diagnostics_start(void);
void vau_diagnostics_io(int opened, int written, int closed);
void vau_diagnostics_update(unsigned phase, int result, int log_result);
void vau_diagnostics_notice(int, int);
void vau_diagnostics_network(unsigned, int, int);

#endif
