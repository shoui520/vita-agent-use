/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "tls_server.h"
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/sha256.h>
#include <string.h>

static struct vau_tls_server *owner;

static int seed(void *context, unsigned char *out, size_t size)
{
	struct vau_tls_server *s = context;
	unsigned char block[32];
	unsigned char *begin = out;
	size_t total         = size;

	while (size) {
		int rc = s->entropy(s->entropy_context, block, sizeof(block));

		if (rc != 0) {
			mbedtls_platform_zeroize(block, sizeof(block));
			mbedtls_platform_zeroize(begin, total);
			return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
		}

		size_t n = size < sizeof(block) ? size : sizeof(block);

		memcpy(out, block, n);
		out += n;
		size -= n;
	}

	mbedtls_platform_zeroize(block, sizeof(block));
	return 0;
}

static int verify_peer(void *context, mbedtls_x509_crt *cert, int depth, uint32_t *flags)
{
	struct vau_tls_server *s = context;

	if (depth == 0) {
		unsigned char hash[32];
		int rc = mbedtls_sha256(cert->raw.p, cert->raw.len, hash, 0);

		if (rc || mbedtls_ct_memcmp(hash, s->peer_fingerprint, sizeof(hash)))
			*flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		mbedtls_platform_zeroize(hash, sizeof(hash));
	}

	/* Never clear chain/signature/usage verification errors. */
	return 0;
}

void vau_tls_server_free(struct vau_tls_server *s)
{
	if (!s || owner != s)
		return;

	mbedtls_ssl_free(&s->channel);
	mbedtls_ssl_config_free(&s->config);
	mbedtls_pk_free(&s->key);
	mbedtls_x509_crt_free(&s->peer);
	mbedtls_x509_crt_free(&s->certificate);
	mbedtls_ctr_drbg_free(&s->rng);
	mbedtls_memory_buffer_alloc_free();
	mbedtls_platform_zeroize(s, sizeof(*s));
	owner = NULL;
}

static int valid_der(struct vau_tls_der der)
{
	return der.data && der.size && der.size <= VAU_TLS_CREDENTIAL_BYTES;
}

static int initialize(struct vau_tls_server *s, struct vau_tls_der certificate,
                      struct vau_tls_der key, struct vau_tls_der peer, vau_entropy entropy,
                      void *context, void (*fatal)(int), int pairing)
{
	if (!s || !entropy || !fatal || !valid_der(certificate) || !valid_der(key) ||
	    (!pairing && !valid_der(peer))) {
		return VAU_INVALID;
	}

	if (owner)
		return VAU_BUSY;

	memset(s, 0, sizeof(*s));
	s->pairing         = pairing;
	s->entropy         = entropy;
	s->entropy_context = context;

	int rc = mbedtls_platform_set_exit(fatal);

	if (rc)
		return rc;

	owner = s;
	mbedtls_memory_buffer_alloc_init(s->arena.bytes, sizeof(s->arena.bytes));
	mbedtls_ctr_drbg_init(&s->rng);
	mbedtls_x509_crt_init(&s->certificate);
	mbedtls_x509_crt_init(&s->peer);
	mbedtls_pk_init(&s->key);
	mbedtls_ssl_config_init(&s->config);
	mbedtls_ssl_init(&s->channel);
	rc = mbedtls_ctr_drbg_seed(&s->rng, seed, s, (const unsigned char *)"vita-agent-tls", 14);
	if (!rc)
		rc = mbedtls_x509_crt_parse_der(&s->certificate, certificate.data, certificate.size);
	if (!rc && !pairing)
		rc = mbedtls_x509_crt_parse_der(&s->peer, peer.data, peer.size);
	if (!rc) {
		rc = mbedtls_pk_parse_key(&s->key, key.data, key.size, NULL, 0, mbedtls_ctr_drbg_random,
		                          &s->rng);
	}

	if (!rc)
		rc = mbedtls_pk_check_pair(&s->certificate.pk, &s->key, mbedtls_ctr_drbg_random, &s->rng);
	if (!rc && !pairing)
		rc = mbedtls_sha256(s->peer.raw.p, s->peer.raw.len, s->peer_fingerprint, 0);
	if (!rc) {
		rc = mbedtls_ssl_config_defaults(&s->config, MBEDTLS_SSL_IS_SERVER,
		                                 MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	}

	if (!rc) {
		mbedtls_ssl_conf_rng(&s->config, mbedtls_ctr_drbg_random, &s->rng);
		mbedtls_ssl_conf_authmode(&s->config, pairing ? MBEDTLS_SSL_VERIFY_OPTIONAL
		                                              : MBEDTLS_SSL_VERIFY_REQUIRED);
		if (!pairing) {
			mbedtls_ssl_conf_ca_chain(&s->config, &s->peer, NULL);
			mbedtls_ssl_conf_verify(&s->config, verify_peer, s);
		}

		rc = mbedtls_ssl_conf_own_cert(&s->config, &s->certificate, &s->key);
	}

	if (!rc)
		rc = mbedtls_ssl_setup(&s->channel, &s->config);
	if (rc) {
		vau_tls_server_free(s);
		return rc;
	}

	s->ready = 1;
	return VAU_OK;
}

int vau_tls_server_init(struct vau_tls_server *s, struct vau_tls_der certificate,
                        struct vau_tls_der key, struct vau_tls_der peer, vau_entropy entropy,
                        void *context, void (*fatal)(int))
{
	return initialize(s, certificate, key, peer, entropy, context, fatal, 0);
}

int vau_tls_server_init_pairing(struct vau_tls_server *s, struct vau_tls_der certificate,
                                struct vau_tls_der key, vau_entropy entropy, void *context,
                                void (*fatal)(int))
{
	return initialize(s, certificate, key, (struct vau_tls_der){ 0 }, entropy, context, fatal, 1);
}

int vau_tls_server_reset(struct vau_tls_server *s)
{
	if (!s || owner != s || !s->ready)
		return VAU_INVALID;

	int rc = mbedtls_ssl_session_reset(&s->channel);

	if (rc)
		vau_tls_server_free(s);
	else
		mbedtls_ssl_set_bio(&s->channel, NULL, NULL, NULL, NULL);
	return rc;
}

int vau_tls_generate_identity(struct vau_tls_server *s, unsigned char *certificate,
                              size_t *certificate_size, unsigned char *key, size_t *key_size,
                              vau_entropy entropy, void *context, void (*fatal)(int))
{
	if (!s || !certificate || !certificate_size || !key || !key_size || !entropy || !fatal)
		return VAU_INVALID;
	if (owner)
		return VAU_BUSY;

	*certificate_size = *key_size = 0;
	memset(s, 0, sizeof(*s));
	s->entropy         = entropy;
	s->entropy_context = context;

	int rc = mbedtls_platform_set_exit(fatal);

	if (rc)
		return rc;

	owner = s;
	mbedtls_memory_buffer_alloc_init(s->arena.bytes, sizeof(s->arena.bytes));
	mbedtls_ctr_drbg_init(&s->rng);
	mbedtls_pk_init(&s->key);

	mbedtls_x509write_cert crt;

	mbedtls_x509write_crt_init(&crt);

	unsigned char serial[16] = { 0 };

	rc = mbedtls_ctr_drbg_seed(&s->rng, seed, s, (const unsigned char *)"vita-agent-identity", 19);
	if (!rc)
		rc = mbedtls_pk_setup(&s->key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	if (!rc) {
		rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(s->key),
		                         mbedtls_ctr_drbg_random, &s->rng);
	}

	if (!rc)
		rc = mbedtls_ctr_drbg_random(&s->rng, serial, sizeof(serial));
	serial[0] = (serial[0] & 0x7f) | 1;
	if (!rc)
		rc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&crt, &s->key);
	mbedtls_x509write_crt_set_issuer_key(&crt, &s->key);
	if (!rc)
		rc = mbedtls_x509write_crt_set_subject_name(&crt, "CN=Vita Agent Device");
	if (!rc)
		rc = mbedtls_x509write_crt_set_issuer_name(&crt, "CN=Vita Agent Device");
	if (!rc)
		rc = mbedtls_x509write_crt_set_validity(&crt, "20200101000000", "20991231235959");
	if (!rc)
		rc = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, 0);
	if (!rc) {
		rc = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
		                                                       MBEDTLS_X509_KU_KEY_CERT_SIGN);
	}

	if (!rc) {
		int n = mbedtls_x509write_crt_der(&crt, certificate, VAU_TLS_CREDENTIAL_BYTES,
		                                  mbedtls_ctr_drbg_random, &s->rng);

		if (n <= 0) {
			rc = n ? n : VAU_DEVICE_ERROR;
		} else {
			*certificate_size = (size_t)n;
			memmove(certificate, certificate + VAU_TLS_CREDENTIAL_BYTES - n, (size_t)n);
		}
	}

	if (!rc) {
		int n = mbedtls_pk_write_key_der(&s->key, key, VAU_TLS_CREDENTIAL_BYTES);

		if (n <= 0) {
			rc = n ? n : VAU_DEVICE_ERROR;
		} else {
			*key_size = (size_t)n;
			memmove(key, key + VAU_TLS_CREDENTIAL_BYTES - n, (size_t)n);
		}
	}

	mbedtls_x509write_crt_free(&crt);
	mbedtls_platform_zeroize(serial, sizeof(serial));
	vau_tls_server_free(s);
	if (rc) {
		mbedtls_platform_zeroize(certificate, VAU_TLS_CREDENTIAL_BYTES);
		mbedtls_platform_zeroize(key, VAU_TLS_CREDENTIAL_BYTES);
		*certificate_size = *key_size = 0;
	}

	return rc;
}
