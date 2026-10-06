/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "performance.h"
#include "log_watch.h"
#include "sqlite_json.h"
#include "native_ops.h"
#include "frames_vita.h"
#include "auth.h"
#include "audit_export.h"
#include "writes_vita.h"
#include "acl_vita.h"
#include "content_runtime.h"
#include "package_install.h"
#include "decrypt.h"
#include <psp2/appmgr.h>
#include <psp2/power.h>
#include <psp2/io/devctl.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/rng.h>

int vau_vita_entropy(void *context, void *output, size_t size)
{
	(void)context;
	if (!output || size != VAU_AUTH_TOKEN_BYTES)
		return VAU_INVALID;

	/* Native API accepts at most 64 bytes; grants need exactly 32. Never
	 * substitute clocks, counters or a PRNG when the native call fails. */
	return sceKernelGetRandomNumber(output, (SceSize)size);
}

/* Shell-facing export present in SceAppMgr but absent from SDK appmgr.h. */
extern SceInt32 sceAppMgrGetAppIdByAppId(SceInt32 app_id);

static uint64_t clock_us(void *ctx)
{
	(void)ctx;
	return sceKernelGetSystemTimeWide();
}

static int content_busy(void *ctx)
{
	(void)ctx;
	return vau_vita_content_busy() || vau_vita_install_busy() || vau_vita_decrypt_busy();
}

static int launch(void *ctx, const char *uri)
{
	if (content_busy(ctx))
		return VAU_BUSY;
	return sceAppMgrLaunchAppByUri(0x20000, uri);
}

static int close_app(void *ctx, const char *title)
{
	if (content_busy(ctx))
		return VAU_BUSY;
	return sceAppMgrDestroyAppByName(title);
}

static int display(void *ctx, int on)
{
	(void)ctx;
	if (!on) {
		/* An empty app inventory does not mean Shell's async workers are idle. */
		if (content_busy(ctx) || vau_vita_approval_pending(ctx))
			return VAU_BUSY;

		int busy = vau_vita_performance_busy();

		if (busy)
			return busy < 0 ? busy : VAU_BUSY;

		VauStatus status = { 0 };
		int rc           = vauInputGetStatus(&status);

		if (rc < 0)
			return rc;
		if (status.size != sizeof(status) || status.abi != VAU_ABI)
			return VAU_DEVICE_ERROR;
		if (status.state == VAU_QUEUED || status.state == VAU_RUNNING ||
		    status.lease_until_us > clock_us(ctx))
			return VAU_BUSY;

		(void)vau_vita_file_list_reset();
		(void)vau_content_legacy_reset();
	}

	return on ? scePowerRequestDisplayOn() : scePowerRequestDisplayOff();
}

int vau_vita_wake(void *ctx)
{
	(void)ctx;

	int rc = scePowerRequestDisplayOn();

	if (rc < 0)
		return rc;

	/* Display request returns before Ctrl restores the physical button mask.
	 * Short bounded sleeps leave the kernel's independent stop worker running. */
	for (unsigned i = 0; i < 40; i++) {
		VauStopStatus status = { 0 };

		rc = vauInputGetStopStatus(&status);
		if (rc < 0)
			return rc;
		if (status.stopped || status.chord_held)
			return VAU_DENIED;
		if (status.ready && !status.observation_error)
			return VAU_OK;

		rc = sceKernelDelayThread(25000);
		if (rc < 0)
			return rc;
	}

	return VAU_DENIED;
}

static int reboot(void *ctx)
{
	(void)ctx;
	if (content_busy(ctx))
		return VAU_BUSY;

	int rc = vau_vita_frames_end();

	if (rc < 0)
		return rc;

	/* Reply has been handed to TLS; give queued network packets time to leave. */
	rc = sceKernelDelayThread(250000);
	return rc < 0 ? rc : scePowerRequestColdReset();
}

static int active_app(void *ctx)
{
	(void)ctx;

	int app = sceAppMgrGetAppIdByAppId(-4);

	/* 3.65 AppMgr returns -1 when its selector resolves to no record.
	 * Permission/API failures have distinct negative error codes. */
	return app == -1 ? 0 : app;
}

static int app_pid(void *ctx, int app)
{
	(void)ctx;
	return sceAppMgrGetProcessIdByAppIdForShell(app);
}

static int app_title(void *ctx, int pid, char title[VAU_TITLE_BYTES])
{
	(void)ctx;

	char name[SCE_APPMGR_MAX_APP_NAME_LENGTH + 1] = { 0 };
	int rc                                        = sceAppMgrGetNameById(pid, name);

	if (rc < 0)
		return rc;
	if (!vau_title_valid(name) && sceClibStrncmp(name, "main", 5))
		return VAU_DEVICE_ERROR;

	sceClibMemcpy(title, name, VAU_TITLE_BYTES);
	return rc;
}

static int battery_percent(void *ctx)
{
	(void)ctx;
	return scePowerGetBatteryLifePercent();
}

static int battery_charging(void *ctx)
{
	(void)ctx;
	return scePowerIsBatteryCharging();
}

static int storage(void *ctx, uint64_t *free_bytes, uint64_t *total_bytes)
{
	(void)ctx;

	SceIoDevInfo info = { 0 };
	int rc            = sceIoDevctl("ux0:", 0x3001, NULL, 0, &info, sizeof(info));

	if (rc >= 0) {
		*free_bytes  = info.free_size;
		*total_bytes = info.max_size;
	}

	return rc;
}
static struct vau_frames frames;

static int capture_frame(void *context, struct vau_frame *out)
{
	(void)context;
	if (!out)
		return VAU_INVALID;

	sceClibMemset(out, 0, sizeof(*out));
	if (!frames.ready) {
		if (frames.allocated) {
			out->failure_stage = VAU_FRAME_STAGE_CLEANUP;

			int rc = vau_frames_end(&frames);

			if (rc < 0)
				return rc;
		}

		out->failure_stage = VAU_FRAME_STAGE_POOL;

		int rc = vau_frames_init(&frames, 64);

		if (rc < 0)
			return rc;
	}

	return vau_frames_capture(&frames, out);
}

static void release_frame(void *context)
{
	(void)context;
	vau_frames_release(&frames);
}

int vau_vita_frames_end(void)
{
	return vau_frames_end(&frames);
}

static void approval_poll(void *ctx)
{
	vau_vita_file_list_idle(clock_us(ctx));
	vau_content_legacy_idle(clock_us(ctx));
	if (vau_vita_content_busy()) {
		(void)vau_vita_file_list_reset();
		(void)vau_content_legacy_reset();
	}

	vau_vita_install_poll();
	vau_vita_decrypt_poll();
	vau_vita_approval_poll(ctx);
}

static int install_guarded(void *ctx, uint64_t owner, const char *subject, const char *id,
                           const char *path, int start, char *out, size_t cap)
{
	if (start && vau_vita_decrypt_busy())
		return VAU_BUSY;
	return vau_vita_install(ctx, owner, subject, id, path, start, out, cap);
}

static int install_guarded_upload(void *ctx, const struct vau_upload_message *m,
                                  struct vau_upload_status *s, struct vau_write_record *r)
{
	return (vau_vita_install_busy() || vau_vita_decrypt_busy())
	               ? VAU_BUSY
	               : vau_vita_file_upload(ctx, m, s, r);
}

static int install_guarded_content(void *ctx, uint64_t owner, const char *subject,
                                   const struct vau_content_query *q, char *out, size_t cap)
{
	if ((vau_vita_install_busy() || vau_vita_decrypt_busy()) &&
	    (q->operation == VAU_CONTENT_PREVIEW || q->operation == VAU_CONTENT_REQUEST)) {
		return VAU_BUSY;
	}

	return vau_vita_content_query(ctx, owner, subject, q, out, cap);
}
const struct vau_native_api vau_vita_native_api = { .clock               = clock_us,
	                                                .launch              = launch,
	                                                .close               = close_app,
	                                                .display             = display,
	                                                .wake                = vau_vita_wake,
	                                                .reboot              = reboot,
	                                                .active_app          = active_app,
	                                                .app_pid             = app_pid,
	                                                .app_title           = app_title,
	                                                .confirmation_button = vau_vita_confirm_mask,
	                                                .system_language     = vau_vita_system_language,
	                                                .system_ui_overlaid =
	                                                        vau_vita_system_ui_overlaid,
	                                                .console_id        = vau_vita_console_id,
	                                                .model             = vau_vita_model,
	                                                .firmware          = vau_vita_firmware,
	                                                .performance       = vau_vita_performance,
	                                                .plugin_list       = vau_vita_plugin_list,
	                                                .metadata          = vau_vita_metadata,
	                                                .touch_panel       = vau_vita_touch_panel,
	                                                .memory            = vau_vita_memory,
	                                                .battery_percent   = battery_percent,
	                                                .battery_charging  = battery_charging,
	                                                .storage           = storage,
	                                                .metadata_error    = vau_vita_metadata_error,
	                                                .livearea_blob     = vau_vita_livearea_blob,
	                                                .livearea_layout   = vau_vita_livearea_layout,
	                                                .content_inventory = vau_vita_content_inventory,
	                                                .content_query     = install_guarded_content,
	                                                .log_watch         = vau_vita_log_watch,
	                                                .livearea_schema   = vau_vita_livearea_schema,
	                                                .events            = vau_vita_events,
	                                                .tty               = vau_vita_tty,
	                                                .dialog_events     = vau_vita_dialog_events,
	                                                .app_list          = vau_vita_app_list,
	                                                .app_running       = vau_vita_app_running,
	                                                .app_install       = install_guarded,
	                                                .decrypt           = vau_vita_decrypt,
	                                                .file_stat         = vau_vita_file_stat,
	                                                .file_list         = vau_vita_file_list,
	                                                .file_read         = vau_vita_file_read,
	                                                .audit_export      = vau_vita_audit_export,
	                                                .file_mutate       = vau_vita_file_mutate,
	                                                .file_upload       = install_guarded_upload,
	                                                .acl               = vau_vita_acl,
	                                                .acl_audit         = vau_vita_acl_audit_read,
	                                                .approval_poll     = approval_poll,
	                                                .approval_cancel   = vau_vita_approval_cancel,
	                                                .approval_pending  = vau_vita_approval_pending,
	                                                .content_busy      = content_busy,
	                                                .frame             = capture_frame,
	                                                .release_frame     = release_frame };
