/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_DIALOG_VITA_H
#define VAU_DIALOG_VITA_H

#include "dialog_callbacks.h"
#include "pairing_prompt.h"

/* Shell 3.65 UI-thread only, after the owner has checked UI availability,
 * inhibited remote input and bound this prompt to immutable peer identity.
 * This low-level function does not establish physical consent or grant trust.
 * On entering native Open, callbacks are consumed and the pair becomes empty,
 * including on native failure. Earlier failures leave the pair caller-owned.
 * native_id receives the native dialog ID/error only if Open is entered.
 * Shared resources must remain loaded throughout the dialog lifetime. */
int vau_dialog_open(const struct vau_pairing_prompt *prompt,
                    struct vau_dialog_callback_pair *callbacks, int32_t *native_id);

/* Caller closes only its own live ID, once. Cleanup callbacks can be deferred. */
void vau_dialog_close(int32_t native_id);

/* Shell UI-thread only. Resident OK-only information dialog. Closing it never
 * changes pairing, stop state, or authorization. */
int vau_dialog_agent_stopped(void);

#endif
