/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_DIALOG_CALLBACKS_H
#define VAU_DIALOG_CALLBACKS_H

#include <stdint.h>
#include "vita_agent.h"

enum vau_dialog_callback_kind {
	VAU_DIALOG_RESULT,
	VAU_DIALOG_LIFECYCLE
};
struct vau_dialog_callback;

/* Native 3.65 vtables have two destructor slots followed by an event method.
 * Lifecycle events take only this; result events also take dialog ID/result. */
struct vau_dialog_result_vtable {
	void (*destroy)(struct vau_dialog_callback *);
	void (*delete_object)(struct vau_dialog_callback *);
	void (*event)(struct vau_dialog_callback *, int32_t, int32_t);
};

struct vau_dialog_lifecycle_vtable {
	void (*destroy)(struct vau_dialog_callback *);
	void (*delete_object)(struct vau_dialog_callback *);
	void (*event)(struct vau_dialog_callback *);
};

struct vau_dialog_callback_hooks {
	void (*result)(void *context, int32_t dialog_id, int32_t button_result);
	void (*lifecycle)(void *context);
	void (*released)(void *context, enum vau_dialog_callback_kind kind);
};

struct vau_dialog_callback_pair {
	struct vau_dialog_callback *result;
	struct vau_dialog_callback *lifecycle;
};

/* UI-thread only. Copies hooks; context/code must outlive BOTH release calls.
 * Result events are raw native observations, never permission grants.
 * Allocate before Open. Open consumes both callbacks even on failure; zero
 * the pair after transferring it and never discard it on an Open error.
 * Only discard while ownership has not yet been transferred to native UI.
 * Initialize the output pair to zero. Allocation failure leaves it empty and
 * calls no hooks. A populated output is rejected without changing ownership.
 * Release callbacks must not unload this module or free callback objects. */
int vau_dialog_callbacks_create(struct vau_dialog_callback_pair *out,
                                const struct vau_dialog_callback_hooks *hooks, void *context);
void vau_dialog_callbacks_discard(struct vau_dialog_callback_pair *owned);

#endif
