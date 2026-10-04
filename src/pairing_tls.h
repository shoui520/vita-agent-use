/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_PAIRING_TLS_H
#define VAU_PAIRING_TLS_H
#include "tls_server.h"
#include "tls_driver.h"
#include "pairing_ui.h"
#include "pairing_request.h"
struct vau_pairing_tls {
    struct vau_tls_server *server;
    struct vau_service *service;
    struct vau_pairing_binding binding;
    unsigned char certificate[VAU_TLS_CREDENTIAL_BYTES];
    size_t certificate_size;
    uint64_t started_us,last_us;
    int ready,error,trusted;
    enum vau_tls_work work;
    struct vau_http_request http;
    struct vau_pairing_request request;
    int request_ready;
};
/* Serialized network worker only; nonblocking BIO required. connection is a
 * locally generated non-reused ID. A stopped service may pair, but a new stop,
 * unhealthy monitor or held stop chord cancels the attempt. */
int vau_pairing_tls_init(struct vau_pairing_tls *p,struct vau_tls_server *server,
    struct vau_service *service,uint64_t connection,uint64_t now);
/* Saved-peer session: requires the strict pinned-certificate TLS server.
 * No native pairing dialog; never permits a bootstrap/unknown peer. */
int vau_session_tls_init(struct vau_pairing_tls *p,struct vau_tls_server *server,
    struct vau_service *service,uint64_t connection,uint64_t now);
/* Handshake only: never reads application data, issues tokens, stores trust or
 * invokes commands. ready means possession of the presented private key was
 * proven by TLS, NOT that the peer is approved. Inspect copied certificate and
 * binding only while ready, then pass immutable copies to the local prompt.
 * Even after ready, keep polling stop/deadline. Owner handles socket closure.
 * Do not promote this channel to the command driver. */
enum vau_tls_work vau_pairing_tls_step(struct vau_pairing_tls *p,
    struct vau_service *service,uint64_t now);
/* Optional bootstrap application-data stage. One handshake or TLS read per
 * call, with the same stop/binding/deadline checks. request_ready exposes only
 * a validated display name; never approves a peer or dispatches commands.
 * Keep calling while the UI is pending: EOF/extra data cancels the attempt.
 * Owner supplies the native dialog worker and handles socket closure. */
enum vau_tls_work vau_pairing_tls_request_step(struct vau_pairing_tls *p,
    struct vau_service *service,uint64_t now);
void vau_pairing_tls_close(struct vau_pairing_tls *p,int error);
#endif
