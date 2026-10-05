/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "frames_vita.h"
#include "shell_jpeg.h"
#include <psp2/kernel/threadmgr.h>
#include <psp2/display.h>
#include <psp2/appmgr.h>

extern int sceAppMgrGetAppIdByAppId(int app_id);

#include <string.h>

extern void *vauPafMalloc(size_t size);
extern void vauPafFree(void *pointer);

/* Native capture syscall used by SceShell's PS+START worker on 3.65. */
extern int _sceAppMgrCaptureFrameBufDMACByAppId(int app_id, SceDisplayFrameBuf *buffer);

int vau_frames_end(struct vau_frames *f)
{
	if (!f)
		return VAU_INVALID;
	if (f->borrowed)
		return VAU_BUSY;

	f->ready = 0;
	if (f->allocated)
		vauPafFree(f->jpeg);
	memset(f, 0, sizeof(*f));
	return VAU_OK;
}

int vau_frames_init(struct vau_frames *f, unsigned ratio)
{
	if (!f || !ratio || ratio > 255)
		return VAU_INVALID;
	if (f->allocated || f->ready)
		return VAU_BUSY;

	void *raw           = NULL;
	size_t raw_capacity = 0;
	int rc              = vau_shell_capture_buffer(&raw, &raw_capacity);

	if (rc < 0)
		return rc;

	void *jpeg = vauPafMalloc(VAU_SHELL_JPEG_BYTES);

	if (!jpeg)
		return VAU_DEVICE_ERROR;

	f->allocated = 1;
	f->ratio     = ratio;
	f->raw       = raw;
	f->jpeg      = jpeg;
	f->ready     = 1;
	return VAU_OK;
}

int vau_frames_capture(struct vau_frames *f, struct vau_frame *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!f || !f->ready)
		return VAU_INVALID;
	if (f->borrowed)
		return VAU_BUSY;

	out->failure_stage = VAU_FRAME_STAGE_CAPTURE;

	SceDisplayFrameBuf fb = { sizeof(fb), f->raw, 960, 0, 960, 544 };
	int app               = sceAppMgrGetAppIdByAppId(-4);

	if (app < 0 && app != -1)
		return app;

	int pid = app == -1 ? 0 : sceAppMgrGetProcessIdByAppIdForShell(app);

	if (app != -1 && pid <= 0)
		return pid < 0 ? pid : VAU_STALE;

	uint64_t started = sceKernelGetSystemTimeWide();
	int rc;

	if (app == -1) {
		/* No AppMgr app exists at LiveArea. Query/copy the configured primary
		 * display through our native Display bridge, rather than Shell's own
		 * process-local framebuffer (which can be empty). */
		VauFrameInfo info = { 0 };

		rc           = vauScreenCapture(f->raw, VAU_FRAME_RAW_BYTES, &info);
		out->capture = info;
		if (rc >= 0) {
			fb.width       = info.width;
			fb.height      = info.height;
			fb.pitch       = info.pitch;
			fb.pixelformat = info.pixel_format;
			pid            = info.process_id;
		}
	} else {
		rc = _sceAppMgrCaptureFrameBufDMACByAppId(-5, &fb);
	}

	uint64_t finished = sceKernelGetSystemTimeWide();

	if (rc < 0)
		return rc;
	if (sceAppMgrGetAppIdByAppId(-4) != app)
		return VAU_STALE;
	if (fb.base != f->raw || fb.pixelformat != 0 || !fb.width || fb.width > 960 || !fb.height ||
	    fb.height > 544 || fb.pitch < fb.width || fb.pitch > 960) {
		return VAU_DEVICE_ERROR;
	}

	out->failure_stage = VAU_FRAME_STAGE_JPEG_ENCODE;

	size_t bytes = 0;

	rc = vau_shell_jpeg(f->raw, fb.width, fb.height, fb.pitch, f->jpeg, VAU_SHELL_JPEG_BYTES,
	                    f->ratio, &bytes);
	if (rc < 0)
		return rc;

	out->capture       = (VauFrameInfo){ .size         = sizeof(VauFrameInfo),
		                                 .abi          = VAU_ABI,
		                                 .width        = fb.width,
		                                 .height       = fb.height,
		                                 .pitch        = fb.pitch,
		                                 .pixel_format = 0,
		                                 .bytes        = fb.pitch * fb.height * 4,
		                                 .process_id   = pid,
		                                 .started_us   = started,
		                                 .finished_us  = finished };
	out->failure_stage = VAU_FRAME_STAGE_NONE;
	out->jpeg          = f->jpeg;
	out->jpeg_bytes    = bytes;
	f->borrowed        = 1;
	return VAU_OK;
}

void vau_frames_release(struct vau_frames *f)
{
	if (f)
		f->borrowed = 0;
}
