/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "format.h"
#include "http.h"
#include <string.h>
#include <stdio.h>

void vau_http_init(struct vau_http_request *r)
{
	memset(r, 0, sizeof(*r));
}

void vau_http_init_pairing(struct vau_http_request *r)
{
	vau_http_init(r);
	r->pairing_only     = 1;
	r->close_connection = 1;
}

void vau_http_init_session(struct vau_http_request *r)
{
	vau_http_init(r);
	r->pairing_only     = 2;
	r->close_connection = 1;
}

void vau_http_init_admission(struct vau_http_request *r)
{
	vau_http_init(r);
	r->pairing_only     = 3;
	r->close_connection = 1;
}

static enum vau_http_state fail(struct vau_http_request *r, unsigned status)
{
	r->state        = VAU_HTTP_ERROR;
	r->error_status = status;
	memset(r->token, 0, sizeof(r->token));
	return r->state;
}

static int equal(const char *a, size_t n, const char *b)
{
	if (strlen(b) != n)
		return 0;

	for (size_t i = 0; i < n; ++i) {
		char c = a[i];

		if (c >= 'A' && c <= 'Z')
			c = (char)(c + 'a' - 'A');
		if (c != b[i])
			return 0;
	}

	return 1;
}

static int token_char(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
	       (c && strchr("!#$%&'*+-.^_`|~", c));
}

static unsigned headers(struct vau_http_request *r)
{
	static const char first[]   = "POST /v1/command HTTP/1.1\r\n";
	static const char file[]    = "POST /v1/file/read HTTP/1.1\r\n";
	static const char audit[]   = "POST /v1/audit HTTP/1.1\r\n";
	static const char upload[]  = "POST /v1/file/upload HTTP/1.1\r\n";
	static const char frame[]   = "POST /v1/frame HTTP/1.1\r\n";
	static const char pair[]    = "POST /v1/pair HTTP/1.1\r\n";
	static const char session[] = "POST /v1/session HTTP/1.1\r\n";
	size_t pos;

	if (r->pairing_only == 3) {
		if (r->header_bytes >= sizeof(session) + 1 &&
		    !memcmp(r->data, session, sizeof(session) - 1)) {
			r->pairing_only = 2;
			pos             = sizeof(session) - 1;
		} else if (r->header_bytes >= sizeof(pair) + 1 &&
		           !memcmp(r->data, pair, sizeof(pair) - 1)) {
			r->pairing_only = 1;
			pos             = sizeof(pair) - 1;
		} else {
			return 400;
		}
	} else if (r->pairing_only == 2) {
		if (r->header_bytes < sizeof(session) + 1 || memcmp(r->data, session, sizeof(session) - 1))
			return 400;

		pos = sizeof(session) - 1;
	} else if (r->pairing_only) {
		if (r->header_bytes < sizeof(pair) + 1 || memcmp(r->data, pair, sizeof(pair) - 1))
			return 400;

		pos = sizeof(pair) - 1;
	} else if (r->header_bytes >= sizeof(first) + 1 && !memcmp(r->data, first, sizeof(first) - 1)) {
		pos = sizeof(first) - 1;
	} else if (r->header_bytes >= sizeof(frame) + 1 && !memcmp(r->data, frame, sizeof(frame) - 1)) {
		pos              = sizeof(frame) - 1;
		r->frame_request = 1;
	} else if (r->header_bytes >= sizeof(file) + 1 && !memcmp(r->data, file, sizeof(file) - 1)) {
		pos                  = sizeof(file) - 1;
		r->file_read_request = 1;
	} else if (r->header_bytes >= sizeof(audit) + 1 && !memcmp(r->data, audit, sizeof(audit) - 1)) {
		pos              = sizeof(audit) - 1;
		r->audit_request = 1;
	} else if (r->header_bytes >= sizeof(upload) + 1 &&
	           !memcmp(r->data, upload, sizeof(upload) - 1)) {
		pos               = sizeof(upload) - 1;
		r->upload_request = 1;
	} else {
		return 400;
	}

	unsigned seen = 0;

	while (pos < r->header_bytes - 2) {
		size_t end = pos;

		while (end + 1 < r->header_bytes && !(r->data[end] == '\r' && r->data[end + 1] == '\n')) {
			if ((unsigned char)r->data[end] < 32 || (unsigned char)r->data[end] > 126)
				return 400;

			++end;
		}

		if (end + 1 >= r->header_bytes || end == pos)
			return 400;

		size_t colon = pos;

		while (colon < end && token_char((unsigned char)r->data[colon]))
			++colon;
		if (colon == pos || colon == end || r->data[colon] != ':')
			return 400;

		size_t begin = colon + 1, finish = end;

		while (begin < finish && r->data[begin] == ' ')
			++begin;
		while (finish > begin && r->data[finish - 1] == ' ')
			--finish;

		const char *name = r->data + pos, *v = r->data + begin;
		size_t name_len = colon - pos, n = finish - begin;
		unsigned bit = 0;

		if (equal(name, name_len, "host")) {
			bit = 1;
			if (!n)
				return 400;
		} else if (equal(name, name_len, "content-length")) {
			bit = 2;
			if (!n || n > 10)
				return 400;

			size_t length = 0;

			for (size_t i = 0; i < n; ++i) {
				if (v[i] < '0' || v[i] > '9')
					return 400;

				length = length * 10 + (unsigned)(v[i] - '0');
				if (length > (r->pairing_only ? VAU_PAIRING_REQUEST_BYTES : VAU_REQUEST_BYTES))
					return 413;
			}

			if (!length)
				return 400;

			r->body_bytes = length;
		} else if (equal(name, name_len, "content-type")) {
			bit = 4;
			if (!equal(v, n, r->upload_request ? "application/octet-stream" : "application/json"))
				return 415;
		} else if (equal(name, name_len, "authorization")) {
			if (r->pairing_only)
				return 400;

			bit = 8;
			if (n != 7 + VAU_TOKEN_HEX_BYTES || !equal(v, 6, "bearer") || v[6] != ' ')
				return 401;

			for (size_t i = 0; i < VAU_TOKEN_HEX_BYTES; ++i) {
				char c = v[7 + i];

				if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
					return 401;

				r->token[i] = c;
			}

			r->token[VAU_TOKEN_HEX_BYTES] = 0;
		} else if (equal(name, name_len, "connection")) {
			bit = 16;
			if (equal(v, n, "close"))
				r->close_connection = 1;
			else if (!equal(v, n, "keep-alive"))
				return 400;
			else if (r->pairing_only)
				return 400;
		} else if (equal(name, name_len, "transfer-encoding") || equal(name, name_len, "expect") ||
		           equal(name, name_len, "upgrade") || equal(name, name_len, "content-encoding")) {
			return 400;
		}

		if (bit && (seen & bit))
			return 400;

		seen |= bit;
		pos = end + 2;
	}

	if (r->pairing_only)
		return (seen & 7) == 7 ? 0 : 400;
	if (!(seen & 8))
		return 401;
	return (seen & 15) == 15 ? 0 : 400;
}

enum vau_http_state vau_http_feed(struct vau_http_request *r, const void *data, size_t size)
{
	if (!r)
		return VAU_HTTP_ERROR;
	if (r->state == VAU_HTTP_ERROR)
		return r->state;
	if ((!data && size) || (r->state == VAU_HTTP_READY && size))
		return fail(r, 400);

	const char *input = data;

	for (size_t i = 0; i < size; ++i) {
		if (!r->header_bytes) {
			if (r->used == VAU_HTTP_HEADER_BYTES)
				return fail(r, 431);

			r->data[r->used++] = input[i];
			if (r->used >= 4 && !memcmp(r->data + r->used - 4, "\r\n\r\n", 4)) {
				r->header_bytes = r->used;

				unsigned status = headers(r);

				if (status)
					return fail(r, status);
			}
		} else {
			if (r->used == r->header_bytes + r->body_bytes)
				return fail(r, 400);

			r->data[r->used++] = input[i];
		}
	}

	if (r->header_bytes && r->used == r->header_bytes + r->body_bytes) {
		r->data[r->used] = 0;
		r->state         = VAU_HTTP_READY;
	}

	return r->state;
}

enum vau_http_state vau_http_eof(struct vau_http_request *r)
{
	if (!r)
		return VAU_HTTP_ERROR;
	return r->state == VAU_HTTP_MORE ? fail(r, 400) : r->state;
}

int vau_http_response_header(char *out, size_t capacity, unsigned status, size_t body_bytes)
{
	return vau_http_response_header_ex(out, capacity, status, body_bytes, 0);
}

static int response_header(char *out, size_t capacity, unsigned status, size_t body_bytes,
                           unsigned keep_alive, size_t limit)
{
	const char *reason;

	switch (status) {
	case 200: reason = "OK"; break;
	case 400: reason = "Bad Request"; break;
	case 401: reason = "Unauthorized"; break;
	case 403: reason = "Forbidden"; break;
	case 413: reason = "Content Too Large"; break;
	case 415: reason = "Unsupported Media Type"; break;
	case 431: reason = "Request Header Fields Too Large"; break;
	case 500: reason = "Internal Server Error"; break;
	default: return VAU_INVALID;
	}

	if (!out || !capacity || body_bytes > limit || keep_alive > 1)
		return VAU_INVALID;

	int n = vau_snprintf(out, capacity,
	                     "HTTP/1.1 %u %s\r\nContent-Type: application/json\r\n"
	                     "Content-Length: %u\r\nConnection: %s\r\nCache-Control: no-store\r\n"
	                     "X-Content-Type-Options: nosniff\r\n\r\n",
	                     status, reason, (unsigned)body_bytes,
	                     keep_alive && (status == 200 || status == 500) ? "keep-alive" : "close");

	return n < 0 || (size_t)n >= capacity ? VAU_INVALID : n;
}

int vau_http_response_header_ex(char *out, size_t capacity, unsigned status, size_t body_bytes,
                                unsigned keep_alive)
{
	return response_header(out, capacity, status, body_bytes, keep_alive, VAU_RESPONSE_BYTES);
}

int vau_http_audit_response_header(char *out, size_t capacity, unsigned status, size_t body_bytes,
                                   unsigned keep_alive)
{
	return response_header(out, capacity, status, body_bytes, keep_alive, VAU_FILE_READ_BYTES);
}
