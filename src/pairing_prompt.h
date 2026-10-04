/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_PAIRING_PROMPT_H
#define VAU_PAIRING_PROMPT_H
#include "notification.h"
#define VAU_PAIRING_TEXT_UNITS 512u
struct vau_pairing_prompt {
    uint16_t text[VAU_PAIRING_TEXT_UNITS];
    size_t length;
};
/* Strict UTF-8 to bounded, NUL-terminated native dialog text. Clears output
 * on any error; unlike agent labels, body text may contain newlines. */
int vau_pairing_prompt_text(struct vau_pairing_prompt *,const char *,size_t);
/* fingerprint is SHA-256 of the exact pending peer's DER certificate. Caller
 * binds that immutable certificate to the native dialog and session. Display
 * labels and this formatting function never authorize a peer by themselves. */
int vau_pairing_prompt_format(struct vau_pairing_prompt *out,
                               const char *name,size_t name_length,
                               const unsigned char fingerprint[32]);
#endif
