/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "acl_vita.h"
#include "acl_approval.h"
#include "acl_config.h"
#include "writes_vita.h"
#include "format.h"
#include <string.h>

/* One bounded request; storage is resident until native callbacks release it. */
static struct vau_acl_approval approval;
static struct vau_file_policy before, candidate;
static char request_id[33], subject_id[65], scope[VAU_PATH_MAX];
static int directory, decision_state, stored_error;

void vau_vita_acl_init(struct vau_service *s)
{
	vau_acl_approval_init(&approval, s, &vau_vita_native_api);
}

static int prompt(struct vau_pairing_prompt *out, const char *name, const char *subject,
                  const char *path)
{
	/* Paths are UTF-8. Decode directly into the common dialog's UTF-16 text. */
	char text[2048];
	int n = vau_snprintf(
	        text, sizeof(text),
	        "Allow %s to write?\nCertificate: %s\n\nPath: %s\n\nPermission persists across reboots.\nProtected plugins and tai roots stay protected.\nRisky writes still require --yes.\n\nSelect OK to allow, or Cancel to deny.",
	        name, subject, path);

	if (n < 0 || (size_t)n >= sizeof(text))
		return VAU_INVALID;
	return vau_pairing_prompt_text(out, text, (size_t)n);
}

int vau_vita_acl_pending(void *ctx)
{
	(void)ctx;
	return approval.service && approval.service->approval_pending;
}

void vau_vita_acl_cancel(void *ctx)
{
	(void)ctx;
	vau_acl_approval_cancel(&approval);
}

void vau_vita_acl_poll(void *ctx)
{
	(void)ctx;
	if (!approval.active)
		return;

	int rc = vau_acl_approval_poll(&approval);

	if (rc == VAU_BUSY)
		return;
	if (!decision_state) {
		stored_error = rc;
		if (!rc) {
			/* Re-read current policy and reject races with owner ACL changes. */
			struct vau_file_policy current;

			rc = vau_vita_acl_load(&current);
			if (!rc && memcmp(&current, &before, sizeof(current)))
				rc = VAU_STALE;
			if (!rc)
				rc = vau_acl_grant_prepare(&current, subject_id, scope, directory, &candidate);
			if (!rc)
				rc = vau_vita_acl_audit(subject_id, request_id, scope, "authorized", 0);
			if (!rc) {
				rc = vau_vita_acl_store(&candidate);

				int logged = vau_vita_acl_audit(subject_id, request_id, scope,
				                                rc ? "failed" : "complete", rc);

				if (!rc && logged)
					rc = logged;
			}

			stored_error = rc;
		}

		decision_state = !stored_error ? 2 : stored_error == VAU_DENIED ? 3 : 4;
	}

	(void)vau_acl_approval_finish(&approval);
}

int vau_vita_acl(void *ctx, uint64_t handle, const char *subject, const char *id, const char *path,
                 int request, int *state, int *native_result)
{
	(void)ctx;
	if (!state || !native_result || !subject || !id || strlen(id) != 32)
		return VAU_INVALID;

	*native_result = 0;
	vau_vita_acl_poll(NULL);
	if (!strcmp(id, request_id)) {
		if (strcmp(subject, subject_id) || (request && strcmp(path, scope)))
			return VAU_STALE;

		*state         = decision_state ? decision_state : 1;
		*native_result = stored_error;
		return VAU_OK;
	}

	if (!request)
		return VAU_STALE;
	if (approval.active || vau_vita_acl_pending(NULL))
		return VAU_BUSY;

	struct vau_file_info info;
	int rc = vau_vita_file_stat(NULL, path, &info);

	/* Requests name an existing file or directory; no invented probe paths. */
	if (rc)
		return rc;

	directory = info.kind == VAU_FILE_DIRECTORY;
	if (!directory && info.kind != VAU_FILE_REGULAR)
		return VAU_DENIED;

	rc = vau_vita_acl_load(&before);
	if (rc)
		return rc;

	rc = vau_acl_grant_prepare(&before, subject, path, directory, &candidate);
	if (rc)
		return rc;

	const char *name = "paired computer";
	int live         = 0;

	for (unsigned i = 0; i < VAU_AUTH_SLOTS; ++i) {
		const struct vau_auth_entry *entry = &approval.service->auth.entries[i];

		if (entry->handle == handle && !strcmp(entry->session.subject, subject)) {
			live = 1;
			if (entry->session.agent_name[0])
				name = entry->session.agent_name;
		}
	}

	if (!live)
		return VAU_DENIED;

	struct vau_pairing_prompt message;

	rc = prompt(&message, name, subject, path);
	if (rc)
		return rc;

	rc = vau_acl_approval_begin(&approval, handle, subject, &message);
	if (rc)
		return rc;

	strcpy(request_id, id);
	strcpy(subject_id, subject);
	strcpy(scope, path);
	decision_state = stored_error = 0;
	*state                        = 1;
	return VAU_OK;
}
