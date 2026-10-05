/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_NATIVE_OPS_H
#define VAU_NATIVE_OPS_H

#include <stdint.h>
#include "vita_agent.h"
#include "frame.h"
#include "file_ops.h"
#include "app_registry.h"
#include "write_ops.h"
#include "upload_wire.h"
#include <stddef.h>

#define VAU_TITLE_BYTES 10u

enum vau_content_query_operation {
	VAU_CONTENT_STATUS,
	VAU_CONTENT_CHANGES,
	VAU_CONTENT_AUDIT,
	VAU_CONTENT_PREVIEW,
	VAU_CONTENT_SCOPE,
	VAU_CONTENT_REQUEST,
	VAU_CONTENT_ALBUMS
};

struct vau_content_query {
	unsigned operation, yes;
	unsigned kind, user;
	char id[33], title[10];
	uint64_t before, after, cursor, media_id;
};

enum vau_native_operation {
	VAU_APP_LAUNCH,
	VAU_APP_CLOSE,
	VAU_SCREEN_ON,
	VAU_SCREEN_OFF
};

enum vau_input_operation {
	VAU_INPUT_ACQUIRE,
	VAU_INPUT_HEARTBEAT,
	VAU_INPUT_CANCEL,
	VAU_INPUT_RELEASE,
	VAU_INPUT_STATUS
};

enum vau_native_result {
	VAU_NATIVE_REJECTED,
	VAU_NATIVE_ACCEPTED
};

enum vau_foreground_kind {
	VAU_FOREGROUND_UNKNOWN,
	VAU_FOREGROUND_NONE,
	VAU_FOREGROUND_SHELL,
	VAU_FOREGROUND_APP
};

/* Transport authorization must precede execution. These callbacks use only
 * native APIs; no database or registry writes implement these operations. */
#define VAU_CONSOLE_ID_BYTES 16u

struct vau_console_id {
	unsigned char bytes[VAU_CONSOLE_ID_BYTES];
};

struct vau_memory {
	uint32_t user_free_bytes, cdram_free_bytes, phycont_free_bytes;
};

struct vau_firmware {
	char text[28];
	uint32_t version_code;
};

/* Immutable identity plus live native state. Errors remain per field. */
struct vau_system_metadata {
	struct vau_firmware actual_firmware;

	int actual_firmware_error, model_error;
	char model_name[24], model_raw[17];
	int wifi_enabled, bluetooth_enabled, airplane_mode, mic_muted;
	int network_state, network_error, signal_percent, signal_error, rssi_dbm, rssi_error;
	int ip_error, mac_error, imei_error, imei_applicable;
	char ip_address[16], mac_address[18], imei[20];
};

void vau_metadata_init(struct vau_system_metadata *out);
int vau_metadata_model(const unsigned char leaf[512], struct vau_system_metadata *out);
struct vau_console_snapshot;
int vau_metadata_json(const struct vau_console_snapshot *snapshot, char *out, size_t capacity);

struct vau_touch_panel {
	int32_t min_active_x, min_active_y, max_active_x, max_active_y;

	int32_t min_display_x, min_display_y, max_display_x, max_display_y;
	uint32_t min_force, max_force;
};

int vau_firmware_valid(const struct vau_firmware *firmware);

struct vau_native_api {
	void *context;
	uint64_t (*clock)(void *context);
	int (*launch)(void *context, const char *uri);
	int (*close)(void *context, const char *title);
	int (*display)(void *context, int on);
	int (*wake)(void *context); /* Wake display and await native input sampling. */
	/* Only transport response completion invokes this terminal operation. */
	int (*reboot)(void *context);
	int (*active_app)(void *context);
	int (*app_pid)(void *context, int app);
	int (*app_title)(void *context, int pid, char title[VAU_TITLE_BYTES]);
	int (*confirmation_button)(void *context);
	int (*system_language)(void *context);
	int (*system_ui_overlaid)(void *context);
	int (*console_id)(void *context, struct vau_console_id *out);
	int (*model)(void *context);
	int (*firmware)(void *context, struct vau_firmware *out);
	void (*metadata)(void *context, struct vau_system_metadata *out);
	int (*touch_panel)(void *context, unsigned port, struct vau_touch_panel *out);
	int (*battery_percent)(void *context);
	int (*battery_charging)(void *context);
	int (*memory)(void *context, struct vau_memory *out);
	int (*storage)(void *context, uint64_t *free_bytes, uint64_t *total_bytes);
	int (*performance)(void *, uint64_t owner, unsigned op, uint32_t value, uint32_t after, char *,
	                   size_t);
	int (*metadata_error)(void *, char *, size_t);
	int (*content_inventory)(void *, const char *, const char *, char *, size_t);
	int (*content_query)(void *, uint64_t, const char *, const struct vau_content_query *, char *,
	                     size_t);
	int (*livearea_blob)(void *, const char *, const char *, uint32_t, const char *, uint32_t,
	                     char *, size_t);
	int (*livearea_layout)(void *, const char *, uint32_t, char *, size_t);
	int (*livearea_schema)(void *, const char *, char *, size_t);
	int (*log_watch)(void *, const char *, uint32_t, const char *, const char *, uint32_t, char *,
	                 size_t);
	int (*dialog_events)(void *, uint32_t, uint32_t, char *, size_t);
	int (*events)(void *context, uint32_t operation, uint32_t after, char *out, size_t capacity);
	int (*app_running)(void *context, char *out, size_t capacity);
	int (*app_install)(void *, uint64_t, const char *, const char *, const char *, int, char *,
	                   size_t);
	int (*plugin_list)(void *context, uint32_t offset, char *out, size_t capacity);
	int (*app_list)(void *context, const char *after, const char *query, struct vau_app_page *out);

	vau_file_stat_fn file_stat;
	vau_file_list_fn file_list;
	vau_file_read_fn file_read;

	int (*audit_export)(void *context, uint64_t after, char *output, size_t capacity);
	int (*file_mutate)(void *context, const struct vau_write_request *, struct vau_write_record *);
	int (*file_upload)(void *context, const struct vau_upload_message *, struct vau_upload_status *,
	                   struct vau_write_record *);
	int (*acl)(void *, uint64_t handle, const char *subject, const char *request_id,
	           const char *path, int request, int *state, int *native_result);
	int (*acl_audit)(void *, uint32_t, char *, size_t);
	void (*approval_poll)(void *);
	void (*approval_cancel)(void *);
	int (*approval_pending)(void *);
	int (*content_busy)(void *); /* Durable native mutation owns the filesystem. */
	/* Successful frame capture loans one JPEG until release_frame. */
	int (*frame)(void *context, struct vau_frame *out);
	void (*release_frame)(void *context);

	void *input_context;

	int (*input)(void *context, uint64_t handle, enum vau_input_operation op, VauStatus *status,
	             uint64_t *lease_until);
	int (*input_submit)(void *context, uint64_t handle, const VauSequence *sequence,
	                    const VauEvent *events, uint64_t *execution_id);
	int (*input_acquire_process)(void *context, uint64_t handle, int32_t process,
	                             uint64_t *lease_until);
	int (*input_submit_touch)(void *context, uint64_t handle, const VauSequence *sequence,
	                          const VauEvent *events, const VauTouchState *touch,
	                          uint64_t *execution_id);
	int (*input_enqueue)(void *context, uint64_t handle, const VauSequence *sequence,
	                     const VauEvent *events, const VauTouchState *touch,
	                     uint64_t *execution_id);
};

struct vau_native_reply {
	uint64_t observed_us;
	int state, native_result;
};

struct vau_foreground {
	uint64_t observed_us;

	int error, app_id, pid, kind;
	char title[VAU_TITLE_BYTES];
};

struct vau_console_snapshot {
	uint64_t begin_us, end_us;

	struct vau_foreground foreground;

	/* Negative values are native errors, never silently converted to zero. */
	int battery_percent, battery_charging, storage_error;
	int confirmation_button, system_language, system_ui_overlaid, model, firmware_error,
	        console_id_error;
	int memory_error;
	struct vau_memory memory;
	struct vau_console_id console_id;
	struct vau_firmware firmware;
	struct vau_system_metadata metadata;
	uint64_t free_bytes, total_bytes;
};

int vau_title_valid(const char *title);
int vau_native_execute(const struct vau_native_api *api, enum vau_native_operation op,
                       const char *title, struct vau_native_reply *reply);
int vau_native_foreground(const struct vau_native_api *api, struct vau_foreground *out);
void vau_native_snapshot(const struct vau_native_api *api, struct vau_console_snapshot *out);
extern const struct vau_native_api vau_vita_native_api;
int vau_vita_wake(void *context);

/* Native worker calls on idle/shutdown after all frame loans are released. */
int vau_vita_frames_end(void);
int vau_vita_confirmation_button(uint32_t *mask);
int vau_vita_confirm_mask(void *context);
int vau_vita_system_language(void *context);
int vau_vita_system_ui_overlaid(void *context);
int vau_vita_model(void *context);
int vau_vita_console_id(void *context, struct vau_console_id *out);
int vau_vita_firmware(void *context, struct vau_firmware *out);
int vau_livearea_blob(const char *, const char *, const char *, uint32_t, const char *, uint32_t,
                      char *, size_t);
int vau_vita_livearea_blob(void *, const char *, const char *, uint32_t, const char *, uint32_t,
                           char *, size_t);
int vau_livearea_layout(const char *, const char *, uint32_t, char *, size_t);
int vau_vita_livearea_layout(void *, const char *, uint32_t, char *, size_t);
int vau_livearea_schema(const char *, const char *, char *, size_t);
int vau_vita_livearea_schema(void *, const char *, char *, size_t);
int vau_vita_dialog_events(void *, uint32_t, uint32_t, char *, size_t);
int vau_vita_events(void *context, uint32_t operation, uint32_t after, char *out, size_t capacity);
int vau_vita_app_running(void *context, char *out, size_t capacity);
int vau_vita_plugin_list(void *context, uint32_t offset, char *out, size_t capacity);
void vau_vita_metadata(void *context, struct vau_system_metadata *out);
int vau_vita_memory(void *context, struct vau_memory *out);
int vau_vita_touch_panel(void *context, unsigned port, struct vau_touch_panel *out);

int vau_content_inventory(const char *, const char *, const char *, char *, size_t);
int vau_vita_content_inventory(void *, const char *, const char *, char *, size_t);

int vau_content_legacy_reset(void);
void vau_content_legacy_idle(uint64_t);
int vau_content_legacy_category(const char *);
int vau_content_legacy_inventory(const char *, const char *, char *, size_t);

#endif
