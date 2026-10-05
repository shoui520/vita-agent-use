/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_TLS_SERVER_H
#define VAU_TLS_SERVER_H

#include "auth.h"
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

/* Host interop peaks below 64 KiB, including near-8 KiB peer certificates.
 * Keep 128 KiB for handshake/fragmentation headroom, without a Shell-sized heap. */
#define VAU_TLS_ARENA_BYTES      (128u * 1024u)
#define VAU_TLS_CREDENTIAL_BYTES 8192u

struct vau_tls_der {
	const unsigned char *data;
	size_t size;
};

/* Allocate in worker-owned static/heap storage, never on its small stack.
 * One instance may own this library's global fixed allocator at a time.
 * All crypto operations, initialization and cleanup use that same worker. */
struct vau_tls_server {
	union {
		uint64_t alignment;
		unsigned char bytes[VAU_TLS_ARENA_BYTES];
	} arena;

	mbedtls_ctr_drbg_context rng;
	mbedtls_x509_crt certificate, peer;
	mbedtls_pk_context key;
	mbedtls_ssl_config config;
	mbedtls_ssl_context channel;
	vau_entropy entropy;
	void *entropy_context;
	unsigned char peer_fingerprint[32];
	int ready, pairing;
};

/* peer must come from trusted local pairing storage, never an unapproved
 * network request. Pins the exact approved DER certificate as well as checking
 * its chain. No public-CA trust or device wall-clock validation is used.
 * entropy must fill exactly 32 bytes per call from the native RNG.
 * fatal must NOT return or exit Shell: it must stop only the owning worker and
 * leave the module resident for diagnosis. Caller supplies this before crypto.
 * DER input is copied/parsed and may be wiped after return. */
int vau_tls_server_init(struct vau_tls_server *s, struct vau_tls_der certificate,
                        struct vau_tls_der key, struct vau_tls_der peer, vau_entropy entropy,
                        void *context, void (*fatal)(int));

/* Quarantined bootstrap only: requests a peer certificate without trusting it.
 * Use only the pairing handshake driver, never command dispatch. No certificate
 * verification errors are cleared. Local approval/storage is a separate step. */
int vau_tls_server_init_pairing(struct vau_tls_server *s, struct vau_tls_der certificate,
                                struct vau_tls_der key, vau_entropy entropy, void *context,
                                void (*fatal)(int));

/* After closing the previous socket and discarding its driver, prepare a new
 * channel using the same identity/configuration; BIO must be installed anew. */
/* First-boot identity generation reuses this server's existing fixed arena.
 * DER output survives teardown; no additional heap/arena is retained. */
int vau_tls_generate_identity(struct vau_tls_server *s, unsigned char *certificate,
                              size_t *certificate_size, unsigned char *key, size_t *key_size,
                              vau_entropy entropy, void *context, void (*fatal)(int));
int vau_tls_server_reset(struct vau_tls_server *s);
void vau_tls_server_free(struct vau_tls_server *s);

#endif
