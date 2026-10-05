/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_delete.h"
#include "format.h"
#include <string.h>

void vau_content_approval_init(struct vau_content_approval *w, struct vau_service *service,
                               const struct vau_native_api *api)
{
	memset(w, 0, sizeof(*w));
	vau_acl_approval_init(&w->ui, service, api);
}

int vau_content_approval_begin(void *context, const struct vau_content_delete_request *request)
{
	struct vau_content_approval *w = context;

	if (!w || !request || !w->ui.service || !w->ui.api || !w->ui.api->clock ||
	    !memchr(request->subject, 0, sizeof(request->subject)) || strlen(request->subject) != 64 ||
	    !memchr(request->title, 0, sizeof(request->title)) || !vau_title_valid(request->title) ||
	    !strncmp(request->title, "NPXS", 4) || request->yes != 1 ||
	    request->kind > VAU_CONTENT_VITA_SAVEDATA || request->user >= 64 ||
	    (request->kind == VAU_CONTENT_APPLICATION && request->user) ||
	    (request->kind == VAU_CONTENT_VITA_SAVEDATA && w->legacy_application) ||
	    (w->shared_savedata != 0 && w->shared_savedata != 1) ||
	    (w->legacy_application != 0 && w->legacy_application != 1)) {
		return VAU_INVALID;
	}

	if (w->ui.active || w->ui.service->approval_pending)
		return VAU_BUSY;

	uint64_t now                      = w->ui.api->clock(w->ui.api->context);
	const struct vau_session *session = NULL;

	for (unsigned i = 0; i < VAU_AUTH_SLOTS; i++) {
		const struct vau_auth_entry *entry = &w->ui.service->auth.entries[i];

		if (w->handle && entry->handle == w->handle && now < entry->expires_us &&
		    (entry->session.rights & VAU_RIGHT_CONTROL) &&
		    !strcmp(entry->session.subject, request->subject)) {
			session = &entry->session;
		}
	}

	if (!session)
		return VAU_DENIED;

	const char *name = session->agent_name[0] ? session->agent_name : "paired computer";
	char text[1024];
	int n;

	if (request->kind == VAU_CONTENT_VITA_SAVEDATA) {
		n = vau_snprintf(
		        text, sizeof(text),
		        "Permanently delete savedata for %s?\nUser: %02u\nRequested by: %s\n\nThe live "
		        "save, matching native backup and staging leftovers may be removed.\nThe "
		        "application remains installed.\n\nReview the full affected paths on your "
		        "computer.\n\nSelect OK to delete, or Cancel to keep.",
		        request->title, request->user, name);
	} else if (w->legacy_application) {
		n = vau_snprintf(
		        text, sizeof(text),
		        "Permanently delete %s?\nRequested by: %s\n\nApplication and metadata will be "
		        "removed. %s\nPSP/PlayStation savedata is not part of this operation.\nNative "
		        "staging leftovers may also be removed.\n\nReview the full affected paths on your "
		        "computer.\n\nSelect OK to delete, or Cancel to keep.",
		        request->title, name,
		        w->shared_savedata ? "Sony's API normally keeps shared game data."
		                           : "Private game data may also be removed.");
	} else {
		n = vau_snprintf(
		        text, sizeof(text),
		        "Permanently delete %s?\nRequested by: %s\n\nApplication, updates, add-ons, licenses, metadata "
		        "and %s\nNative staging leftovers may also be removed.\n\nReview the full affected paths on your "
		        "computer.\n\nSelect OK to delete, or Cancel to keep.",
		        request->title, name,
		        w->shared_savedata
		                ? "cache will be removed. Sony's API normally keeps shared savedata."
		                : "private savedata and cache will be removed.");
	}

	if (n < 0 || (size_t)n >= sizeof(text))
		return VAU_INVALID;

	struct vau_pairing_prompt prompt;
	int rc = vau_pairing_prompt_text(&prompt, text, (size_t)n);

	if (rc)
		return rc;

	rc = vau_acl_approval_begin(&w->ui, w->handle, request->subject, &prompt);
	if (!rc)
		w->finished = 0;
	return rc;
}

int vau_content_approval_poll(void *context)
{
	struct vau_content_approval *w = context;

	return w ? vau_acl_approval_poll(&w->ui) : VAU_INVALID;
}

int vau_content_approval_finish(void *context)
{
	struct vau_content_approval *w = context;

	if (!w)
		return VAU_INVALID;
	if (w->finished)
		return VAU_OK;

	int rc = vau_acl_approval_finish(&w->ui);

	if (!rc)
		w->finished = 1;
	return rc;
}

void vau_content_approval_cancel(struct vau_content_approval *w)
{
	if (w)
		vau_acl_approval_cancel(&w->ui);
}
