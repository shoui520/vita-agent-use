/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_TLS_DRIVER_H
#define VAU_TLS_DRIVER_H
#include "connection.h"
#include <mbedtls/ssl.h>

#define VAU_TLS_HANDSHAKE_US UINT64_C(10000000)
enum vau_tls_work { VAU_TLS_RUN, VAU_TLS_WAIT_READ, VAU_TLS_WAIT_WRITE, VAU_TLS_CLOSED };
struct vau_tls_driver {
    struct vau_connection connection;
    mbedtls_ssl_context *tls;
    unsigned char input[1024];
    uint64_t started_us, last_us, generation;
    int active, error;
    enum vau_tls_work work;
};
/* User-mode only. Owner configures a fresh server context with native entropy,
 * fixed allocator, trusted peer credentials and VERIFY_REQUIRED, and installs
 * nonblocking BIO callbacks before init. Driver borrows the context; owner must
 * close its socket and free/reset TLS when CLOSED. Never reuse a failed context
 * without reset. Each driver has exactly one owner; serialize with the service.
 * No pairing/identity provisioning takes place through this command driver. */
int vau_tls_driver_init(struct vau_tls_driver *d, mbedtls_ssl_context *tls,
                         struct vau_service *s, uint64_t now);
/* One TLS operation per call. RUN may be scheduled again; WAIT_* needs socket
 * readiness or a <=16ms stop/deadline poll. BIO callbacks must never block.
 * A handshake step may itself perform costly public-key work; this is not a
 * hard CPU-time bound. Kernel stop handling remains independently scheduled. */
enum vau_tls_work vau_tls_driver_step(struct vau_tls_driver *d,
                                      struct vau_service *s,
                                      const struct vau_native_api *api, uint64_t now);
void vau_tls_driver_close(struct vau_tls_driver *d, int error);
#endif
