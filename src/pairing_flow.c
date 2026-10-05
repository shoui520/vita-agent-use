/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pairing_flow.h"
#include <string.h>

int vau_pairing_flow_init(struct vau_pairing_flow *f, struct vau_pairing_tls *tls,
                          struct vau_pairing_worker *ui)
{
	if (!f)
		return VAU_INVALID;

	memset(f, 0, sizeof(*f));
	if (!tls || !ui || !ui->service || tls->service != ui->service || !ui->service->auth.stopped ||
	    ui->state != VAU_PAIR_WORK_IDLE || !tls->server || !tls->server->ready ||
	    !tls->server->pairing || tls->work == VAU_TLS_CLOSED || !tls->binding.connection) {
		return VAU_DENIED;
	}

	f->tls        = tls;
	f->ui         = ui;
	f->connection = tls->binding.connection;
	return VAU_OK;
}

void vau_pairing_flow_cancel(struct vau_pairing_flow *f, int error)
{
	if (!f || !f->tls || !f->ui)
		return;
	if (!f->error)
		f->error = error < 0 ? error : VAU_DENIED;
	vau_pairing_tls_close(f->tls, f->error);
	vau_pairing_worker_cancel(f->ui);

	/* Local cancellation after an OK must not leave a grant that never reached
	 * the host. Input-owner polling releases a revoked native lease. */
	if (f->ui->state == VAU_PAIR_WORK_DONE && f->ui->grant.handle) {
		if (!f->ui->service->auth.stopped)
			vau_auth_stop(&f->ui->service->auth);
		(void)vau_service_poll(f->ui->service);

		volatile unsigned char *grant = (volatile unsigned char *)&f->ui->grant;

		for (size_t i = 0; i < sizeof(f->ui->grant); i++)
			grant[i] = 0;
	}
}

int vau_pairing_flow_step(struct vau_pairing_flow *f, uint64_t now)
{
	if (!f || !f->tls || !f->ui)
		return VAU_INVALID;
	if (f->complete)
		return f->error;

	struct vau_pairing_tls *tls   = f->tls;
	struct vau_pairing_worker *ui = f->ui;

	if (!f->error) {
		if (tls->binding.connection != f->connection)
			vau_pairing_flow_cancel(f, VAU_STALE);
		else if (vau_pairing_tls_request_step(tls, ui->service, now) == VAU_TLS_CLOSED)
			vau_pairing_flow_cancel(f, tls->error);
	}

	if (!f->begun && !f->error && tls->request_ready) {
		int rc = vau_pairing_worker_begin(ui, &tls->binding, tls->request.name,
		                                  tls->request.name_length, now);

		/* A failed native enqueue can still own callbacks. Keep draining when
		 * begin entered PENDING, even if its returned status is an error. */
		f->begun = ui->state != VAU_PAIR_WORK_IDLE;
		if (rc < 0)
			vau_pairing_flow_cancel(f, rc);
	}

	if (f->begun) {
		const struct vau_pairing_binding *current = f->error ? NULL : &tls->binding;
		int rc                                    = vau_pairing_worker_poll(ui, current, now);

		if (ui->state != VAU_PAIR_WORK_DONE)
			return VAU_BUSY;
		if (rc < 0 && !f->error)
			vau_pairing_flow_cancel(f, rc);
		if (f->error)
			vau_pairing_flow_cancel(f, f->error);
		f->complete = 1;
		return f->error;
	}

	if (f->error) {
		f->complete = 1;
		return f->error;
	}

	return VAU_BUSY;
}
