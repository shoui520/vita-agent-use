/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "native_ops.h"
#include "json.h"
#include "format.h"
#include <string.h>

void vau_metadata_init(struct vau_system_metadata *out)
{
	memset(out, 0, sizeof(*out));
	out->actual_firmware_error = out->model_error = VAU_UNSUPPORTED;
	out->wifi_enabled = out->bluetooth_enabled = out->airplane_mode = out->mic_muted =
	        VAU_UNSUPPORTED;
	out->network_error = out->signal_error = out->rssi_error = out->ip_error = out->mac_error =
	        out->imei_error                                                  = VAU_UNSUPPORTED;
	out->imei_applicable                                                     = -1;
}

int vau_metadata_model(const unsigned char leaf[512], struct vau_system_metadata *out)
{
	if (!leaf || !out)
		return VAU_INVALID;

	/* PSVident's retail IdStorage model layout; never substitute a guessed
	 * regional model for an unknown/prototype layout. */
	if (memcmp(leaf, "PCH0", 4) && memcmp(leaf, "VTE0", 4))
		return VAU_UNSUPPORTED;

	for (unsigned i = 0; i < 16; i++)
		if (leaf[i] < 0x20 || leaf[i] > 0x7e)
			return VAU_DEVICE_ERROR;
	for (unsigned i = 4; i < 8; i++)
		if (leaf[i] < '0' || leaf[i] > '9')
			return VAU_DEVICE_ERROR;
	memcpy(out->model_raw, leaf, 16);
	out->model_raw[16] = 0;
	memcpy(out->model_name, leaf, 3);
	out->model_name[3] = '-';
	memcpy(out->model_name + 4, leaf + 4, 4);
	out->model_name[8]   = 0;
	out->imei_applicable = memcmp(leaf, "PCH011", 6) == 0;
	return VAU_OK;
}

static const char *boolean(int value)
{
	return value < 0 || value > 1 ? "null" : value ? "true" : "false";
}

static int error(int value)
{
	return value < 0 ? value : 0;
}

static const char *number(int value, int rc, char out[24])
{
	if (rc < 0)
		return "null";

	vau_snprintf(out, 24, "%d", value);
	return out;
}

static const char *quote(const char *value, size_t bytes, int rc, char *out, size_t cap)
{
	if (rc < 0 || !memchr(value, 0, bytes) || !value[0] || vau_json_quote(value, out, cap) < 0)
		return "null";
	return out;
}

static void storage_display(uint64_t bytes, int rc, char out[24])
{
	if (rc < 0) {
		memcpy(out, "null", 5);
		return;
	}

	/* NPXS10015 3.65 converts bytes to integer KiB before this formatter. */
	uint32_t kib = (uint32_t)(bytes >> 10);

	if (kib < 10000)
		vau_snprintf(out, 24, "\"%u KB\"", kib);
	else if (kib <= 0x9c3c00u)
		vau_snprintf(out, 24, "\"%u MB\"", kib >> 10);
	else
		vau_snprintf(out, 24, "\"%u GB\"", kib >> 20);
}

int vau_metadata_json(const struct vau_console_snapshot *s, char *out, size_t cap)
{
	const struct vau_system_metadata *m = &s->metadata;
	char fw[171], model[147], raw[105], ip[99], mac[111], imei[123];
	char code[24], state[24], signal[24], rssi[24], reported[171], capacity_display[24],
	        free_display[24];

	storage_display(s->total_bytes, s->storage_error, capacity_display);
	storage_display(s->free_bytes, s->storage_error, free_display);
	vau_snprintf(code, sizeof(code), "%u", m->actual_firmware.version_code);
	return vau_snprintf(
	        out, cap,
	        ",\"actual_firmware\":{\"version\":%s,\"version_code\":%s,\"error_code\":%d},"
	        "\"model_identity\":{\"name\":%s,\"raw\":%s,\"error_code\":%d},"
	        "\"wifi\":{\"enabled\":%s,\"enabled_error_code\":%d,\"state\":%s,\"state_error_code\":%d,"
	        "\"strength_percent\":%s,\"strength_error_code\":%d,\"rssi_dbm\":%s,\"rssi_error_code\":%d,\"ip_address\":%s,\"ip_error_code\":%d},"
	        "\"bluetooth\":{\"enabled\":%s,\"error_code\":%d},"
	        "\"airplane_mode\":{\"enabled\":%s,\"error_code\":%d},"
	        "\"mic_muted\":{\"value\":%s,\"error_code\":%d},"
	        "\"mac_address\":{\"value\":%s,\"source\":\"current_network_interface\",\"error_code\":%d},"
	        "\"imei\":{\"applicable\":%s,\"value\":%s,\"error_code\":%d},"
	        "\"confirmation_symbol\":%s,\"plugins\":{\"operation\":\"plugins.list\"},"
	        "\"settings_system_information\":{\"title_id\":\"NPXS10015\",\"firmware_version\":%s,\"mac_address\":%s,"
	        "\"imei\":%s,\"memory_card\":{\"mount\":\"ux0:\",\"capacity_display\":%s,\"free_display\":%s,\"error_code\":%d}}}}",
	        quote(m->actual_firmware.text, sizeof(m->actual_firmware.text),
	              m->actual_firmware_error, fw, sizeof(fw)),
	        m->actual_firmware_error < 0 ? "null" : code, error(m->actual_firmware_error),
	        quote(m->model_name, sizeof(m->model_name), m->model_error, model, sizeof(model)),
	        quote(m->model_raw, sizeof(m->model_raw), m->model_error, raw, sizeof(raw)),
	        error(m->model_error), boolean(m->wifi_enabled), error(m->wifi_enabled),
	        number(m->network_state, m->network_error, state), error(m->network_error),
	        number(m->signal_percent, m->signal_error, signal), error(m->signal_error),
	        number(m->rssi_dbm, m->rssi_error, rssi), error(m->rssi_error),
	        quote(m->ip_address, sizeof(m->ip_address), m->ip_error, ip, sizeof(ip)),
	        error(m->ip_error), boolean(m->bluetooth_enabled), error(m->bluetooth_enabled),
	        boolean(m->airplane_mode), error(m->airplane_mode), boolean(m->mic_muted),
	        error(m->mic_muted),
	        quote(m->mac_address, sizeof(m->mac_address), m->mac_error, mac, sizeof(mac)),
	        error(m->mac_error), boolean(m->imei_applicable),
	        quote(m->imei, sizeof(m->imei), m->imei_error, imei, sizeof(imei)),
	        error(m->imei_error),
	        s->confirmation_button < 0         ? "null"
	        : s->confirmation_button == 0x4000 ? "\"×\""
	                                           : "\"〇\"",
	        quote(s->firmware.text, sizeof(s->firmware.text), s->firmware_error, reported,
	              sizeof(reported)),
	        quote(m->mac_address, sizeof(m->mac_address), m->mac_error, mac, sizeof(mac)),
	        m->imei_applicable == 0
	                ? "null"
	                : quote(m->imei, sizeof(m->imei), m->imei_error, imei, sizeof(imei)),
	        capacity_display, free_display, error(s->storage_error));
}
