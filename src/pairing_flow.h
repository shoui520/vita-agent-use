/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_PAIRING_FLOW_H
#define VAU_PAIRING_FLOW_H

#include "pairing_tls.h"
#include "pairing_worker.h"

/*
 * First pairing, end to end:
 *
 *   pairing_tls         handshake; proves the PC holds its key (not approval)
 *   pairing_request     reads and validates the display name it sends
 *   pairing_worker      posts the dialog to the Shell UI thread and waits
 *   pairing_ui          the native OK/Cancel prompt itself
 *   pairing_activation  on OK: issues the grant and its token
 *
 * This flow sequences those steps; shell_runtime then stores the peer
 * certificate (store_peer) and delivers the token.
 */

/* Borrowed resident objects, owned by one serialized Shell worker. Native UI
 * modules must be ready and the owner must check dialog coexistence before
 * allowing this attempt, as required by pairing_worker_begin. This coordinator
 * does not replace that native readiness guard or create a listener. */
struct vau_pairing_flow {
	struct vau_pairing_tls *tls;
	struct vau_pairing_worker *ui;
	uint64_t connection;
	int begun, complete, error;
};

int vau_pairing_flow_init(struct vau_pairing_flow *flow, struct vau_pairing_tls *tls,
                          struct vau_pairing_worker *ui);

/* VAU_BUSY while receiving/waiting/draining callbacks, VAU_OK after native OK,
 * otherwise the terminal error. Poll <=16ms apart, including after TLS closes
 * until complete. Network readiness hints remain in tls->work; a closed TLS
 * channel still needs timed UI cleanup polls, never a socket wait on its old fd.
 * On success the owner consumes ui->grant and tls->certificate for protected
 * persistence/token delivery. No command dispatch or trust writes occur here.
 * Do not reset/reuse either borrowed object while this flow is pending. */
int vau_pairing_flow_step(struct vau_pairing_flow *flow, uint64_t now_us);

/* Local disconnect/shutdown path. A pending native UI still must drain via step.
 * Cancel after approval revokes authorization; no automatic resume. */
void vau_pairing_flow_cancel(struct vau_pairing_flow *flow, int error);

#endif
