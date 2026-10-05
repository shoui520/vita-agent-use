/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_media_capture_vita.h"
#include "native_ops.h"
#include <string.h>

void vau_vita_media_capture_init(struct vau_media_capture_vita *c, void *context,
                                 int (*stop)(void *))
{
	if (!c)
		return;

	memset(c, 0, sizeof(*c));
	vau_vita_media_session_init(&c->paths, context, stop);
	c->initialized = 1;
}

static int cleanup(struct vau_media_capture_vita *c)
{
	int rc = 0;

	if (c->path_cleanup) {
		rc = vau_media_session_close(&c->paths.session);
		if (!rc)
			c->path_cleanup = 0;
	}

	if (c->source_cleanup) {
		int end = vau_media_source_close(&c->source);

		if (!end)
			c->source_cleanup = 0;
		if (!rc)
			rc = end;
	}

	return rc;
}

int vau_vita_media_capture_cleanup(struct vau_media_capture_vita *c)
{
	if (!c || !c->initialized)
		return VAU_INVALID;
	if (c->busy)
		return VAU_BUSY;

	c->busy = 1;

	int rc = cleanup(c);

	c->busy = 0;
	return rc;
}

int vau_vita_media_capture(struct vau_media_capture_vita *c, struct vau_content_scope_writer *w,
                           const struct vau_file_policy *policy, uint64_t before,
                           const struct vau_content_capture_adapter *adapter)
{
	if (!c || !c->initialized || !w || !w->journal || !w->scope.sequence ||
	    w->journal->scope_active != w->scope.sequence || w->failure || w->media_added ||
	    w->scope.request.kind < VAU_CONTENT_PHOTO || !adapter || !adapter->stopped ||
	    !adapter->observe || ((w->scope.phase == VAU_CONTENT_SCOPE_AFTER) != (before != 0))) {
		return VAU_INVALID;
	}

	if (w->scope.phase == VAU_CONTENT_SCOPE_AFTER) {
		if (!adapter->walk)
			return VAU_INVALID;
	} else if (!policy || vau_policy_validate(policy)) {
		return VAU_INVALID;
	}

	if (c->busy || c->path_cleanup || c->source_cleanup)
		return VAU_BUSY;

	c->busy = 1;

	int rc            = adapter->stopped(adapter->context) ? VAU_EXPIRED : 0;
	unsigned category = w->scope.request.kind - VAU_CONTENT_PHOTO + 1;

	if (!rc) {
		c->source_cleanup = 1;
		rc                = vau_vita_media_source_open(&c->source, category);
		if (rc && w->scope.phase == VAU_CONTENT_SCOPE_AFTER) {
			rc = vau_content_capture_media_unavailable(w, before, rc, adapter);
		} else if (!rc) {
			if (w->scope.phase != VAU_CONTENT_SCOPE_AFTER) {
				c->path_cleanup = 1;
				rc              = vau_media_session_open(&c->paths.session, category, 0);
			}

			if (!rc) {
				rc = vau_content_capture_media_view(w, policy, &c->paths.session, &c->source,
				                                    before, adapter);
			}

			if (!rc && w->scope.phase != VAU_CONTENT_SCOPE_AFTER) {
				struct vau_media_temp_directory temp;

				rc = vau_vita_media_temp_directory(&c->paths.session, &temp);
				if (!rc)
					rc = vau_content_capture_media_temp(w, policy, &temp, adapter);
			}
		}
	}

	int end = cleanup(c);

	if (!rc)
		rc = end;
	if (rc && !w->failure)
		w->failure = rc;
	c->busy = 0;
	return rc;
}
