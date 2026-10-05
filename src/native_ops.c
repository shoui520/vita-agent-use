/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "native_ops.h"
#include "json.h"
#include <string.h>

int vau_title_valid(const char *title)
{
	if (!title)
		return 0;

	for (unsigned i = 0; i < VAU_TITLE_BYTES - 1; ++i)
		if (!((title[i] >= 'A' && title[i] <= 'Z') || (title[i] >= '0' && title[i] <= '9')))
			return 0;
	return title[VAU_TITLE_BYTES - 1] == 0;
}

int vau_native_execute(const struct vau_native_api *api, enum vau_native_operation op,
                       const char *title, struct vau_native_reply *reply)
{
	int rc = VAU_INVALID;

	if (!api || !reply || !api->clock)
		return VAU_INVALID;

	memset(reply, 0, sizeof(*reply));
	switch (op) {
	case VAU_APP_LAUNCH:
		if (vau_title_valid(title) && api->launch) {
			char uri[sizeof("psgm:play?titleid=") + VAU_TITLE_BYTES - 1];

			memcpy(uri, "psgm:play?titleid=", sizeof("psgm:play?titleid=") - 1);
			memcpy(uri + sizeof("psgm:play?titleid=") - 1, title, VAU_TITLE_BYTES);
			rc = api->launch(api->context, uri);
		}
		break;
	case VAU_APP_CLOSE:
		if (vau_title_valid(title) && api->close)
			rc = api->close(api->context, title);
		break;
	case VAU_SCREEN_ON:
	case VAU_SCREEN_OFF:
		if (!title && api->display)
			rc = api->display(api->context, op == VAU_SCREEN_ON);
		break;
	default: break;
	}

	reply->native_result = rc;
	reply->state         = rc < 0 ? VAU_NATIVE_REJECTED : VAU_NATIVE_ACCEPTED;
	reply->observed_us   = api->clock(api->context);

	/* Acceptance is not confirmation of foreground, termination or panel
	 * state. Observation is a separate operation so input heartbeats need not
	 * wait for a launch animation or a system dialog to finish. */
	return rc;
}

int vau_native_foreground(const struct vau_native_api *api, struct vau_foreground *out)
{
	if (!api || !out || !api->clock)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));

	int rc = VAU_UNSUPPORTED;

	if (!api->active_app || !api->app_pid || !api->app_title)
		goto done;

	out->app_id = api->active_app(api->context);
	if (out->app_id < 0) {
		rc = out->app_id;
		goto done;
	}

	if (!out->app_id) {
		out->kind = VAU_FOREGROUND_NONE;
		rc        = 0;
		goto done;
	}

	out->pid = api->app_pid(api->context, out->app_id);
	if (out->pid < 0) {
		rc = out->pid;
		goto done;
	}

	rc = api->app_title(api->context, out->pid, out->title);
	if (rc < 0)
		goto done;
	if (!memcmp(out->title, "main", 5)) {
		out->kind = VAU_FOREGROUND_SHELL;
	} else if (vau_title_valid(out->title)) {
		out->kind = VAU_FOREGROUND_APP;
	} else {
		rc = VAU_DEVICE_ERROR;
		goto done;
	}

	int active = api->active_app(api->context);

	if (active < 0)
		rc = active;
	else if (active != out->app_id)
		rc = VAU_STALE;
done:
	out->observed_us = api->clock(api->context);
	out->error       = rc < 0 ? rc : 0;
	if (rc < 0) {
		memset(out->title, 0, sizeof(out->title));
		out->kind = VAU_FOREGROUND_UNKNOWN;
	}

	return rc;
}

int vau_firmware_valid(const struct vau_firmware *firmware)
{
	if (!firmware || !memchr(firmware->text, 0, sizeof(firmware->text)))
		return 0;
	if (!firmware->text[0])
		return 0;

	char quoted[171];

	return vau_json_quote(firmware->text, quoted, sizeof(quoted)) >= 0;
}

void vau_native_snapshot(const struct vau_native_api *api, struct vau_console_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	out->begin_us = api->clock(api->context);
	vau_metadata_init(&out->metadata);
	if (api->metadata)
		api->metadata(api->context, &out->metadata);
	vau_native_foreground(api, &out->foreground);
	out->console_id_error =
	        api->console_id ? api->console_id(api->context, &out->console_id) : VAU_UNSUPPORTED;
	if (out->console_id_error < 0)
		memset(&out->console_id, 0, sizeof(out->console_id));
	out->model = api->model ? api->model(api->context) : VAU_UNSUPPORTED;
	out->firmware_error =
	        api->firmware ? api->firmware(api->context, &out->firmware) : VAU_UNSUPPORTED;
	if (out->firmware_error >= 0 && !vau_firmware_valid(&out->firmware))
		out->firmware_error = VAU_DEVICE_ERROR;
	if (out->firmware_error < 0)
		memset(&out->firmware, 0, sizeof(out->firmware));
	out->confirmation_button =
	        api->confirmation_button ? api->confirmation_button(api->context) : VAU_UNSUPPORTED;
	if (out->confirmation_button >= 0 && out->confirmation_button != 0x2000 &&
	    out->confirmation_button != 0x4000) {
		out->confirmation_button = VAU_DEVICE_ERROR;
	}

	out->system_language =
	        api->system_language ? api->system_language(api->context) : VAU_UNSUPPORTED;
	if (out->system_language > 19)
		out->system_language = VAU_DEVICE_ERROR;
	out->system_ui_overlaid =
	        api->system_ui_overlaid ? api->system_ui_overlaid(api->context) : VAU_UNSUPPORTED;
	if (out->system_ui_overlaid > 1)
		out->system_ui_overlaid = VAU_DEVICE_ERROR;
	out->battery_percent =
	        api->battery_percent ? api->battery_percent(api->context) : VAU_UNSUPPORTED;
	if (out->battery_percent > 100)
		out->battery_percent = VAU_DEVICE_ERROR;
	out->battery_charging =
	        api->battery_charging ? api->battery_charging(api->context) : VAU_UNSUPPORTED;
	if (out->battery_charging > 1)
		out->battery_charging = VAU_DEVICE_ERROR;
	out->storage_error = api->storage
	                             ? api->storage(api->context, &out->free_bytes, &out->total_bytes)
	                             : VAU_UNSUPPORTED;
	if (out->storage_error >= 0 && out->free_bytes > out->total_bytes)
		out->storage_error = VAU_DEVICE_ERROR;
	if (out->storage_error < 0)
		out->free_bytes = out->total_bytes = 0;
	/* RAM measurements belong to the explicit performance collector. */
	out->memory_error = VAU_UNSUPPORTED;
	out->end_us       = api->clock(api->context);
}
