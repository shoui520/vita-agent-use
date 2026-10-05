/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "stop_monitor.h"

int vau_stop_ready(const struct vau_stop_monitor *m, uint64_t now)
{
	return m->sampled && !m->error && now >= m->read_us && now - m->read_us < VAU_STOP_STALE_US;
}

int vau_stop_observe(struct vau_stop_monitor *m, int result, uint32_t mask, uint32_t buttons,
                     uint64_t stamp, uint64_t now)
{
	m->raw_stamp      = stamp;
	m->previous_stamp = m->stamp;
	m->observed_us    = now;
	m->result         = result;
	m->mask           = mask;
	m->buttons        = buttons;
	m->reason         = 0;

	/* reason codes are public diagnostics: see VauInputObservation in vita_agent.h. */
	int error = 0;

	if (result < 0) {
		error     = result;
		m->reason = 1;
	} else if (result != 1) {
		error     = VAU_DEVICE_ERROR;
		m->reason = 2;
	} else if ((mask & VAU_STOP_CHORD) != VAU_STOP_CHORD) {
		/* Something masked PS or SELECT, so the emergency stop could go unseen. */
		error     = VAU_DENIED;
		m->reason = 3;
	}

	/* Ctrl publishes a process-relative timestamp. Kernel process samples can
	 * be zero, repeat or wrap near UINT64_MAX. Keep it for diagnostics only;
	 * readiness uses successful reads and the independent system clock. */
	else if (m->sampled && now < m->read_us) {
		error     = VAU_STALE;
		m->reason = 6;
	}

	if (!error) {
		if (!m->sampled || stamp != m->stamp)
			m->changed_us = now;
		m->stamp   = stamp;
		m->read_us = now;
		m->sampled = 1;
	}

	m->error = error;
	if (error) {
		m->fault = 1;
		m->held  = 0;
		return 0;
	}

	m->fault = 0;

	int held  = (buttons & VAU_STOP_CHORD) == VAU_STOP_CHORD;
	int event = held && !m->held;

	m->held = held;
	return event;
}
