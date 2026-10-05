/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "touch_sample.h"
#include <stddef.h>
#include <string.h>

_Static_assert(sizeof(struct vau_touch_contact) == 8, "Touch contact ABI");
_Static_assert(sizeof(struct vau_touch_pose) == 128, "Touch pose ABI");
_Static_assert(sizeof(struct vau_touch_report) == 16, "Native touch report ABI");
_Static_assert(sizeof(struct vau_touch_frame) == 0x90, "Native touch frame ABI");
_Static_assert(offsetof(struct vau_touch_frame, reports) == 0x10, "Native touch report offset");

static int header_valid(const struct vau_touch_pose *p)
{
	return p && p->process >= 0 && !(p->enabled & ~3u) && !p->reserved &&
	       p->changed_us <= p->refreshed_us && p->until_us > p->refreshed_us &&
	       p->until_us - p->refreshed_us <= VAU_TOUCH_REFRESH_US &&
	       p->count[0] <= VAU_TOUCH_FRONT_CONTACTS && p->count[1] <= VAU_TOUCH_BACK_CONTACTS &&
	       ((p->enabled & 1u) || !p->count[0]) && ((p->enabled & 2u) || !p->count[1]);
}

int vau_touch_pose_validate(const struct vau_touch_pose *p, const struct vau_touch_panel panels[2])
{
	if (!header_valid(p) || !panels)
		return VAU_INVALID;

	for (unsigned port = 0; port < 2; port++) {
		if (!(p->enabled & (1u << port)))
			continue;

		const struct vau_touch_panel *panel = &panels[port];

		if (panel->min_active_x >= panel->max_active_x ||
		    panel->min_active_y >= panel->max_active_y || panel->min_force > panel->max_force ||
		    panel->max_force > 255) {
			return VAU_INVALID;
		}

		for (unsigned i = 0; i < p->count[port]; i++) {
			const struct vau_touch_contact *c = &p->contacts[port][i];

			if (c->id >= 128 || c->reserved || c->x < panel->min_active_x ||
			    c->x > panel->max_active_x || c->y < panel->min_active_y ||
			    c->y > panel->max_active_y || c->force < panel->min_force ||
			    c->force > panel->max_force) {
				return VAU_INVALID;
			}

			for (unsigned j = 0; j < i; j++)
				if (c->id == p->contacts[port][j].id)
					return VAU_INVALID;
		}
	}

	return VAU_OK;
}

unsigned vau_touch_override(const struct vau_touch_pose *p, uint64_t now, int32_t process,
                            struct vau_touch_frame *front, struct vau_touch_frame *back,
                            vau_touch_owner owner, void *context)
{
	if (!header_valid(p) || (p->process && (!owner || process != p->process)) ||
	    (front && front == back) || now < p->refreshed_us || now >= p->until_us) {
		return 0;
	}

	struct vau_touch_frame *frames[2] = { front, back };
	unsigned changed                  = 0;

	for (unsigned port = 0; port < 2; port++) {
		struct vau_touch_frame *frame = frames[port];

		if (!(p->enabled & (1u << port)) || !frame || frame->timestamp < p->changed_us ||
		    frame->timestamp > now) {
			continue;
		}

		for (unsigned i = 0; i < p->count[port]; i++) {
			const struct vau_touch_contact *c = &p->contacts[port][i];

			if (p->process && owner(context, port, c->x, c->y) != p->process)
				return 0;
		}

		changed |= 1u << port;
	}

	/* Check both panels before modifying either: a rear contact routed to an
	 * overlay must not leave half of a two-panel gesture published. */
	for (unsigned port = 0; port < 2; port++) {
		if (!(changed & (1u << port)))
			continue;

		struct vau_touch_frame *frame = frames[port];

		memset(frame->reports, 0, sizeof(frame->reports));
		for (unsigned i = 0; i < p->count[port]; i++) {
			const struct vau_touch_contact *c = &p->contacts[port][i];

			frame->reports[i].id    = c->id;
			frame->reports[i].force = c->force;
			frame->reports[i].x     = c->x;
			frame->reports[i].y     = c->y;
		}

		frame->count = p->count[port];
	}

	return changed;
}
