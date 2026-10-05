/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "dialog_vita.h"
#include <stddef.h>
#include <string.h>

struct native_string {
	const uint16_t *text;
	uint32_t length;
	uint32_t reserved;
};

struct dialog_parameters {
	void *resource;

	uint32_t reserved04;
	float position[4], bounds[4];
	uint32_t options, mode;
	int32_t priority;
	uint8_t flag34, flag35;
	uint16_t reserved36;
	int32_t existing_id;
	int32_t *id_output;
	uint32_t flags;
	uint8_t blocking, pad45[3];
	const void *layout[3];
	struct native_string title, message;
	uint32_t reserved6c;
	float geometry[4], animation_speed;
	void *image84, *image88, *image8c;
	struct vau_dialog_callback *result, *lifecycle;
	void *animation_callback;
};
#if defined(__arm__)
_Static_assert(sizeof(struct dialog_parameters) == 0x9c, "3.65 dialog parameter ABI");
_Static_assert(offsetof(struct dialog_parameters, layout) == 0x48, "Dialog layout offset");
_Static_assert(offsetof(struct dialog_parameters, title) == 0x54, "Title offset");
_Static_assert(offsetof(struct dialog_parameters, message) == 0x60, "Message offset");
_Static_assert(offsetof(struct dialog_parameters, geometry) == 0x70, "Geometry offset");
_Static_assert(offsetof(struct dialog_parameters, result) == 0x90, "Result callback offset");
#endif
extern void *vauPafFindPlugin(const char *name);
extern void *vauGuiBaseParameters(void *parameters);
extern int32_t vauGuiOpen(void *parameters);
extern void vauGuiClose(int32_t id);
extern const void *vauGuiOkCancelLayout[3];
extern const void *vauGuiOkLayout[3];

static int open_layout(const struct vau_pairing_prompt *prompt,
                       struct vau_dialog_callback_pair *callbacks, int32_t *native_id,
                       const void *const layout[3])
{
	if (!prompt || !callbacks || !callbacks->result || !callbacks->lifecycle || !native_id ||
	    !prompt->length || prompt->length >= VAU_PAIRING_TEXT_UNITS ||
	    prompt->text[prompt->length]) {
		return VAU_INVALID;
	}

	/* FindPlugin handles an absent toplevel; the base constructor does not. */
	void *resource = vauPafFindPlugin("__system__common_resource");

	if (!resource)
		return VAU_BUSY;

	struct dialog_parameters p;

	memset(&p, 0, sizeof(p));
	vauGuiBaseParameters(&p);
	if (p.resource != resource)
		return VAU_BUSY;

	memcpy(p.layout, layout, sizeof(p.layout));

	/* Native Open consumes string contents synchronously; its normal caller
	 * frees its original strings after return. No native string destructor is
	 * invoked on these borrowed buffers by this adapter. */
	static const uint16_t empty[] = { 0 };

	p.title.text     = empty;
	p.message.text   = prompt->text;
	p.message.length = (uint32_t)prompt->length;
	memcpy(p.geometry, p.position, sizeof(p.geometry));
	p.animation_speed = 1.0f;
	p.result          = callbacks->result;
	p.lifecycle       = callbacks->lifecycle;
	memset(callbacks, 0, sizeof(*callbacks));
	*native_id = vauGuiOpen(&p);
	return *native_id < 0 ? VAU_DEVICE_ERROR : VAU_OK;
}

int vau_dialog_open(const struct vau_pairing_prompt *prompt,
                    struct vau_dialog_callback_pair *callbacks, int32_t *native_id)
{
	return open_layout(prompt, callbacks, native_id, vauGuiOkCancelLayout);
}

void vau_dialog_close(int32_t id)
{
	if (id >= 0)
		vauGuiClose(id);
}

/* Both native callback objects can outlive Open and Close. Keep this context
 * resident until both release callbacks, including synchronous Open callbacks. */
static struct {
	int32_t id;
	unsigned active, opening, closing, decided, released;
} stopped_notice;

static void notice_advance(void)
{
	if (stopped_notice.opening)
		return;
	if (stopped_notice.decided && !stopped_notice.closing && stopped_notice.id >= 0) {
		stopped_notice.closing = 1;
		vau_dialog_close(stopped_notice.id);
	}

	if (stopped_notice.released == 3)
		stopped_notice.active = 0;
}

static void notice_result(void *context, int32_t id, int32_t result)
{
	(void)context;
	(void)id;
	(void)result;
	stopped_notice.decided = 1;
	notice_advance();
}

static void notice_lifecycle(void *context)
{
	(void)context;
	notice_advance();
}

static void notice_released(void *context, enum vau_dialog_callback_kind kind)
{
	(void)context;
	stopped_notice.released |= 1u << kind;
	notice_advance();
}

int vau_dialog_agent_stopped(void)
{
	if (stopped_notice.active)
		return VAU_OK; /* Already visible; no duplicate. */

	memset(&stopped_notice, 0, sizeof(stopped_notice));
	stopped_notice.id     = -1;
	stopped_notice.active = stopped_notice.opening = 1;

	const struct vau_dialog_callback_hooks hooks = { notice_result, notice_lifecycle,
		                                             notice_released };
	struct vau_dialog_callback_pair callbacks    = { 0 };

	int rc = vau_dialog_callbacks_create(&callbacks, &hooks, NULL);

	if (rc < 0) {
		stopped_notice.active = stopped_notice.opening = 0;
		return rc;
	}

	struct vau_pairing_prompt prompt;

	rc = vau_pairing_prompt_text(&prompt, "Agent stopped.", 14);
	if (!rc)
		rc = open_layout(&prompt, &callbacks, &stopped_notice.id, vauGuiOkLayout);
	if (callbacks.result || callbacks.lifecycle)
		vau_dialog_callbacks_discard(&callbacks);
	stopped_notice.opening = 0;
	notice_advance();
	return rc;
}
