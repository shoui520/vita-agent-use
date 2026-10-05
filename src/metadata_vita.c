/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "native_ops.h"
#include "format.h"
#include <psp2/vshbridge.h>
#include <psp2/registrymgr.h>
#include <psp2/audioin.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <string.h>

extern int sceWlanGetConfiguration(void);
extern int sceBtGetConfiguration(void);

static int registry_boolean(const char *category, const char *key)
{
	int value = -1;
	int rc    = sceRegMgrGetKeyInt(category, key, &value);

	if (rc < 0)
		return rc;
	return value == 0 || value == 1 ? value : VAU_DEVICE_ERROR;
}

static void identity(struct vau_system_metadata *out)
{
	SceKernelFwInfo info = { .size = sizeof(info) };

	out->actual_firmware_error = _vshSblGetSystemSwVersion(&info);
	if (out->actual_firmware_error >= 0) {
		memcpy(out->actual_firmware.text, info.versionString, sizeof(info.versionString));
		out->actual_firmware.version_code = info.version;
		if (!vau_firmware_valid(&out->actual_firmware)) {
			memset(&out->actual_firmware, 0, sizeof(out->actual_firmware));
			out->actual_firmware_error = VAU_DEVICE_ERROR;
		}
	}

	unsigned char leaf[512] = { 0 };

	out->model_error = vshIdStorageReadLeaf(0x115, leaf);
	if (out->model_error >= 0)
		out->model_error = vau_metadata_model(leaf, out);
	if (out->imei_applicable == 0) {
		out->imei_error = 0;
	} else if (out->imei_applicable == 1) {
		memset(leaf, 0, sizeof(leaf));
		out->imei_error = vshIdStorageReadLeaf(0x113, leaf);
		if (out->imei_error >= 0) {
			for (unsigned i = 0; i < 15; i++)
				if (leaf[i] < '0' || leaf[i] > '9')
					out->imei_error = VAU_DEVICE_ERROR;
			if (out->imei_error >= 0) {
				vau_snprintf(out->imei, sizeof(out->imei), "%c%c-%c%c%c%c%c%c-%c%c%c%c%c%c-%c",
				             leaf[0], leaf[1], leaf[2], leaf[3], leaf[4], leaf[5], leaf[6], leaf[7],
				             leaf[8], leaf[9], leaf[10], leaf[11], leaf[12], leaf[13], leaf[14]);
			}
		}
	}
}

void vau_vita_metadata(void *context, struct vau_system_metadata *out)
{
	(void)context;
	vau_metadata_init(out);
	identity(out);

	/* These are getters only. Never reinitialize/terminate Shell's shared
	 * network modules or infer radio power from connection state. */
	int config = sceWlanGetConfiguration();

	out->wifi_enabled      = config < 0 ? config : !!(config & 1);
	config                 = sceBtGetConfiguration();
	out->bluetooth_enabled = config < 0 ? config : !!(config & 9);
	out->airplane_mode     = registry_boolean("/CONFIG/SYSTEM", "flight_mode");
	out->mic_muted         = sceAudioInGetStatus(SCE_AUDIO_IN_GETSTATUS_MUTE);
	if (out->mic_muted > 1)
		out->mic_muted = VAU_DEVICE_ERROR;
	out->network_error = sceNetCtlInetGetState(&out->network_state);
	if (out->network_error >= 0 && (out->network_state < 0 || out->network_state > 3))
		out->network_error = VAU_DEVICE_ERROR;

	SceNetCtlInfo info = { 0 };

	out->signal_error = sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_RSSI_PERCENTAGE, &info);
	if (out->signal_error >= 0) {
		if (info.rssi_percentage > 100)
			out->signal_error = VAU_DEVICE_ERROR;
		else
			out->signal_percent = (int)info.rssi_percentage;
	}

	memset(&info, 0, sizeof(info));
	out->rssi_error = sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_RSSI_DBM, &info);
	if (out->rssi_error >= 0)
		out->rssi_dbm = (int32_t)info.rssi_dbm;
	memset(&info, 0, sizeof(info));
	out->ip_error = sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_IP_ADDRESS, &info);
	if (out->ip_error >= 0) {
		if (!memchr(info.ip_address, 0, sizeof(info.ip_address)))
			out->ip_error = VAU_DEVICE_ERROR;
		else
			memcpy(out->ip_address, info.ip_address, sizeof(out->ip_address));
	}

	SceNetEtherAddr mac = { { 0 } };

	out->mac_error = sceNetGetMacAddress(&mac, 0);
	if (out->mac_error >= 0) {
		vau_snprintf(out->mac_address, sizeof(out->mac_address), "%02X:%02X:%02X:%02X:%02X:%02X",
		             mac.data[0], mac.data[1], mac.data[2], mac.data[3], mac.data[4], mac.data[5]);
	}
}
