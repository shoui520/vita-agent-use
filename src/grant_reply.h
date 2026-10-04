/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_GRANT_REPLY_H
#define VAU_GRANT_REPLY_H
#include "pairing_activation.h"
#include <mbedtls/ssl.h>
struct vau_grant_reply_io {
    mbedtls_ssl_context *channel;
    void *context;
    uint64_t (*clock)(void *context);
    int (*wait)(void *context,int write);
};
/* Deliver the supplied live grant over the already authenticated channel.
 * Both native first pairing and saved-peer reconnect use this path. */
int vau_grant_reply(struct vau_service *service,const struct vau_pairing_grant *grant,
    unsigned command_port,const struct vau_grant_reply_io *io);
#endif
