/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pairing_tls.h"
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <string.h>

void vau_pairing_tls_close(struct vau_pairing_tls *p, int error)
{
	if (!p)
		return;

	mbedtls_platform_zeroize(p->certificate, sizeof(p->certificate));
	mbedtls_platform_zeroize(&p->binding, sizeof(p->binding));
	mbedtls_platform_zeroize(&p->http, sizeof(p->http));
	mbedtls_platform_zeroize(&p->request, sizeof(p->request));
	p->request_ready    = 0;
	p->certificate_size = 0;
	p->ready            = 0;
	p->error            = error;
	p->work             = VAU_TLS_CLOSED;
}

static int monitor(struct vau_service *s, int trusted)
{
	if (!s)
		return 0;

	(void)vau_service_poll(s);

	/* Authenticate a saved PC even when the screen-off Ctrl mask is absent.
	 * Actual pairing/control still require wake and full readiness. */
	return s->valid && !s->stop.chord_held &&
	       (trusted ? !s->stop.stopped && !s->stop.generation : 1);
}

static int initialize(struct vau_pairing_tls *p, struct vau_tls_server *server,
                      struct vau_service *s, uint64_t connection, uint64_t now, int trusted)
{
	if (!p)
		return VAU_INVALID;

	memset(p, 0, sizeof(*p));
	if (!server || !server->ready || server->pairing == trusted || !connection ||
	    mbedtls_ssl_is_handshake_over(&server->channel) || !monitor(s, trusted)) {
		vau_pairing_tls_close(p, VAU_DENIED);
		return VAU_DENIED;
	}

	p->trusted    = trusted;
	p->server     = server;
	p->service    = s;
	p->started_us = p->last_us        = now;
	p->binding.connection             = connection;
	p->binding.local_stop_generation  = s->auth.stop_generation;
	p->binding.kernel_stop_generation = s->stop.generation;
	if (trusted)
		vau_http_init_session(&p->http);
	else
		vau_http_init_pairing(&p->http);
	return VAU_OK;
}

int vau_pairing_tls_init(struct vau_pairing_tls *p, struct vau_tls_server *server,
                         struct vau_service *s, uint64_t connection, uint64_t now)
{
	return initialize(p, server, s, connection, now, 0);
}

int vau_session_tls_init(struct vau_pairing_tls *p, struct vau_tls_server *server,
                         struct vau_service *s, uint64_t connection, uint64_t now)
{
	return initialize(p, server, s, connection, now, 1);
}

enum vau_tls_work vau_pairing_tls_step(struct vau_pairing_tls *p, struct vau_service *s,
                                       uint64_t now)
{
	if (!p || p->work == VAU_TLS_CLOSED)
		return VAU_TLS_CLOSED;
	if (s != p->service || !monitor(s, p->trusted) || now < p->last_us ||
	    s->auth.stop_generation != p->binding.local_stop_generation ||
	    s->stop.generation != p->binding.kernel_stop_generation ||
	    now - p->started_us >= (p->ready ? VAU_PAIRING_UI_TIMEOUT_US : VAU_TLS_HANDSHAKE_US)) {
		vau_pairing_tls_close(p, VAU_DENIED);
		return p->work;
	}

	p->last_us = now;
	if (p->ready)
		return p->work = VAU_TLS_WAIT_READ;

	int rc = mbedtls_ssl_handshake_step(&p->server->channel);

	if (rc == MBEDTLS_ERR_SSL_WANT_READ)
		return p->work = VAU_TLS_WAIT_READ;
	if (rc == MBEDTLS_ERR_SSL_WANT_WRITE)
		return p->work = VAU_TLS_WAIT_WRITE;
	if (rc) {
		vau_pairing_tls_close(p, rc);
		return p->work;
	}

	if (mbedtls_ssl_is_handshake_over(&p->server->channel)) {
		const mbedtls_x509_crt *cert = mbedtls_ssl_get_peer_cert(&p->server->channel);
		uint32_t flags               = mbedtls_ssl_get_verify_result(&p->server->channel);

		/* An unknown trust anchor is expected; malformed/usage/key/signature
		 * errors are not. Require a single certificate, not delegated chains. */
		if (!cert || cert->next || !cert->raw.len || cert->raw.len > sizeof(p->certificate) ||
		    (p->trusted ? flags : (flags & ~MBEDTLS_X509_BADCERT_NOT_TRUSTED))) {
			vau_pairing_tls_close(p, VAU_DENIED);
			return p->work;
		}

		rc = mbedtls_sha256(cert->raw.p, cert->raw.len, p->binding.certificate_sha256, 0);
		if (rc) {
			vau_pairing_tls_close(p, rc);
			return p->work;
		}

		memcpy(p->certificate, cert->raw.p, cert->raw.len);
		p->certificate_size = cert->raw.len;
		p->ready            = 1;
	}

	return p->work = VAU_TLS_RUN;
}

enum vau_tls_work vau_pairing_tls_request_step(struct vau_pairing_tls *p, struct vau_service *s,
                                               uint64_t now)
{
	if (!p || p->work == VAU_TLS_CLOSED)
		return VAU_TLS_CLOSED;

	/* Completing a handshake and reading are separate scheduler operations. */
	if (!p->ready)
		return vau_pairing_tls_step(p, s, now);
	if (vau_pairing_tls_step(p, s, now) == VAU_TLS_CLOSED)
		return VAU_TLS_CLOSED;

	unsigned char input[512];
	int rc = mbedtls_ssl_read(&p->server->channel, input, sizeof(input));

	if (rc == MBEDTLS_ERR_SSL_WANT_READ)
		return p->work = VAU_TLS_WAIT_READ;
	if (rc == MBEDTLS_ERR_SSL_WANT_WRITE)
		return p->work = VAU_TLS_WAIT_WRITE;
	if (rc <= 0) {
		vau_pairing_tls_close(p, rc < 0 ? rc : VAU_DENIED);
		return p->work;
	}

	enum vau_http_state state = vau_http_feed(&p->http, input, (size_t)rc);

	mbedtls_platform_zeroize(input, sizeof(input));
	if (state == VAU_HTTP_ERROR ||
	    (state == VAU_HTTP_READY && vau_pairing_request_decode(&p->http, &p->request) < 0)) {
		vau_pairing_tls_close(p, VAU_INVALID);
		return p->work;
	}

	p->request_ready = state == VAU_HTTP_READY;
	return p->work   = VAU_TLS_RUN;
}
