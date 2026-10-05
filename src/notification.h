/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_NOTIFICATION_H
#define VAU_NOTIFICATION_H

#include <stddef.h>
#include <stdint.h>

#define VAU_AGENT_NAME_BYTES 128u

/* Shared single-line UTF-8 label validation. Output needs 128 UTF-16 units;
 * the returned count excludes a terminator. Names are presentation only. */
int vau_agent_name_utf16(uint16_t out[VAU_AGENT_NAME_BYTES], size_t *count, const char *name,
                         size_t length);

/* 3.65 notification_util sends exactly 0x470 bytes to ShellSvc command
 * 0x70007. The installed SDK's 0x410 buffer comment is insufficient. */
struct vau_notification {
	uint16_t text[64];
	char activation_uri[1000];
	uint32_t reserved[2];
};

/* Native ProgressFinish packet has distinct headline/subtitle fields. */
struct vau_styled_notification {
	uint16_t title[64], subtitle[64];

	char activation_uri[1000];
};

/* 3.65 Begin copies 0x570 bytes. Callback/userdata precede the optional
 * third UTF-16 field; the installed SDK's smaller InitParam is incompatible. */
struct vau_notification_begin {
	struct vau_styled_notification message;

	uint32_t callback, userdata;
	uint16_t detail[64];
};

int vau_notification_using_styled(struct vau_styled_notification *, const char *, size_t);
int vau_notification_using(struct vau_notification *out, const char *agent_name, size_t length);

/* User-mode 3.65 native sender. Both NotificationUtil and ShellSvc must already
 * be loaded and remain resident; never initialize/terminate Shell shared modules
 * here. Owner checks active local authorization and stop readiness before use.
 * This synchronous RPC can block: run on a separate notification worker, never
 * on the command/stop worker or the Shell UI thread. Do not send at module start.
 * Native success is API acceptance, not proof of rendering. */
int vau_vita_notification_style_result(void);
int vau_vita_notification_using(const char *agent_name, size_t length);

#endif
