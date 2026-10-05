/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "grant_reply.h"
#include "format.h"
#include <mbedtls/platform_util.h>
#include <string.h>

int vau_grant_reply(struct vau_service *service, const struct vau_pairing_grant *grant,
                    unsigned command_port, const struct vau_grant_reply_io *io)
{
	if (!service || !grant || !io || !io->channel || !io->clock || !io->wait || !command_port ||
	    grant->token[VAU_TOKEN_HEX_BYTES]) {
		return VAU_INVALID;
	}

	char body[256], reply[768];
	int body_size =
	        vau_snprintf(body, sizeof(body), "{\"v\":1,\"token\":\"%s\",\"command_port\":%u}",
	                     grant->token, command_port);

	if (body_size < 0 || (size_t)body_size >= sizeof(body))
		return VAU_INVALID;

	int header_size = vau_http_response_header(reply, sizeof(reply), 200, (size_t)body_size);

	if (header_size < 0 || (size_t)(header_size + body_size) > sizeof(reply))
		return VAU_INVALID;

	memcpy(reply + header_size, body, (size_t)body_size);

	size_t used = 0, total = (size_t)(header_size + body_size);
	uint64_t start = io->clock(io->context);
	int result     = VAU_OK;

	while (used < total) {
		uint64_t now = io->clock(io->context);

		if (now < start || now - start >= UINT64_C(10000000) ||
		    vau_service_transport_poll(service) < 0 ||
		    !vau_auth_lookup(&service->auth, grant->token, VAU_TOKEN_HEX_BYTES, now)) {
			result = VAU_DENIED;
			break;
		}

		int rc = mbedtls_ssl_write(io->channel, (unsigned char *)reply + used, total - used);

		if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
			rc = io->wait(io->context, rc == MBEDTLS_ERR_SSL_WANT_WRITE);
			if (rc < 0) {
				result = rc;
				break;
			}
		} else if (rc <= 0) {
			result = rc < 0 ? rc : VAU_DEVICE_ERROR;
			break;
		} else {
			used += (size_t)rc;
		}
	}

	mbedtls_platform_zeroize(body, sizeof(body));
	mbedtls_platform_zeroize(reply, sizeof(reply));
	return result;
}
