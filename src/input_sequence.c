/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "input_sequence.h"
#include <string.h>

struct button {
	const char *name;
	uint32_t mask;
};
static const struct button buttons[] = {
	{ "SELECT", 1 },      { "START", 8 },     { "UP", 16 },       { "RIGHT", 32 },
	{ "DOWN", 64 },       { "LEFT", 128 },    { "L", 256 },       { "R", 512 },
	{ "TRIANGLE", 4096 }, { "CIRCLE", 8192 }, { "CROSS", 16384 }, { "SQUARE", 32768 }
};

void vau_input_stream_init(struct vau_input_stream *s, void *context,
                           int (*stage)(void *, uint32_t, uint32_t, uint32_t, const void *))
{
	s->stage   = stage;
	s->context = context;
	for (unsigned kind = 0; kind < 2; kind++) {
		vau_sha256_init(&s->hash[kind]);
		s->base[kind] = s->fill[kind] = 0;
	}
}

static unsigned char *chunk(struct vau_input_stream *s, uint32_t kind, size_t *size)
{
	*size = kind == VAU_STAGE_TOUCH ? sizeof(*s->touch) : sizeof(*s->events);
	return kind == VAU_STAGE_TOUCH ? (unsigned char *)s->touch : (unsigned char *)s->events;
}

static int flush(struct vau_input_stream *s, uint32_t kind)
{
	size_t size;
	const unsigned char *entries = chunk(s, kind, &size);

	if (!s->fill[kind])
		return VAU_OK;
	if (!s->stage)
		return VAU_UNSUPPORTED;

	int rc = s->stage(s->context, kind, s->base[kind], s->fill[kind], entries);

	if (rc < 0)
		return rc;

	vau_sha256_update(&s->hash[kind], entries, s->fill[kind] * size);
	s->base[kind] += s->fill[kind];
	s->fill[kind] = 0;
	return VAU_OK;
}

int vau_input_stream_put(struct vau_input_stream *s, uint32_t kind, uint32_t index,
                         const void *entry)
{
	if (kind > VAU_STAGE_TOUCH)
		return VAU_INVALID;

	uint32_t end = s->base[kind] + s->fill[kind];

	if (index == end) {
		/* A new entry makes the newest one final, so a full chunk can go. */
		if (s->fill[kind] == VAU_STAGE_CHUNK) {
			int rc = flush(s, kind);

			if (rc < 0)
				return rc;
		}

		s->fill[kind]++;
	} else if (index + 1 != end || !s->fill[kind]) {
		return VAU_INVALID;
	}

	size_t size;
	unsigned char *entries = chunk(s, kind, &size);

	memcpy(entries + (index - s->base[kind]) * size, entry, size);
	return VAU_OK;
}

int vau_input_stream_finish(struct vau_input_stream *s, unsigned char digests[2][32])
{
	for (uint32_t kind = 0; kind < 2; kind++) {
		int rc = flush(s, kind);

		if (rc < 0)
			return rc;

		vau_sha256_finish(&s->hash[kind], digests[kind]);
	}

	return VAU_OK;
}

static int number(const char *json, const struct vau_json_token *t, unsigned max, unsigned *out)
{
	uint64_t n;

	if (vau_json_u64(json, t, &n) || n > max)
		return VAU_INVALID;

	*out = (unsigned)n;
	return VAU_OK;
}

static int pad_buttons(const char *json, const struct vau_json_token *t, size_t array,
                       uint32_t *out)
{
	if (t[array].type != VAU_JSON_ARRAY)
		return VAU_INVALID;

	*out = 0;
	for (size_t i = array + 1; i < t[array].next; i = t[i].next) {
		char name[16];

		if (vau_json_ascii(json, &t[i], name, sizeof(name)))
			return VAU_INVALID;

		unsigned j;

		for (j = 0; j < sizeof(buttons) / sizeof(*buttons); ++j)
			if (!strcmp(name, buttons[j].name))
				break;
		if (j == sizeof(buttons) / sizeof(*buttons) || (*out & buttons[j].mask))
			return VAU_INVALID;

		*out |= buttons[j].mask;
	}

	return VAU_OK;
}

static int stick(const char *json, const struct vau_json_token *t, size_t array, uint8_t *x,
                 uint8_t *y)
{
	unsigned a, b;

	if (t[array].type != VAU_JSON_ARRAY || t[array].next != array + 3 ||
	    number(json, &t[array + 1], 255, &a) || number(json, &t[array + 2], 255, &b)) {
		return VAU_INVALID;
	}

	*x = (uint8_t)a;
	*y = (uint8_t)b;
	return VAU_OK;
}

static int contacts(const char *json, const struct vau_json_token *t, size_t array, unsigned port,
                    VauTouchState *out)
{
	if (t[array].type != VAU_JSON_ARRAY)
		return VAU_INVALID;

	out->enabled |= (uint8_t)(1u << port);
	out->count[port] = 0;
	memset(out->contacts[port], 0, sizeof(out->contacts[port]));
	for (size_t i = array + 1; i < t[array].next; i = t[i].next) {
		if (t[i].type != VAU_JSON_OBJECT || out->count[port] >= (port ? 4u : 6u))
			return VAU_INVALID;

		unsigned seen     = 0;
		VauTouchContact c = { .force = 128 };

		for (size_t f = i + 1; f < t[i].next; f = t[f + 1].next) {
			char key[16];
			unsigned value, bit;

			if (vau_json_ascii(json, &t[f], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "id")) {
				bit = 1;
				if (number(json, &t[f + 1], 127, &value))
					return VAU_INVALID;

				c.id = (uint8_t)value;
			} else if (!strcmp(key, "x")) {
				bit = 2;
				if (number(json, &t[f + 1], 32767, &value))
					return VAU_INVALID;

				c.x = (int16_t)value;
			} else if (!strcmp(key, "y")) {
				bit = 4;
				if (number(json, &t[f + 1], 32767, &value))
					return VAU_INVALID;

				c.y = (int16_t)value;
			} else if (!strcmp(key, "force")) {
				bit = 8;
				if (number(json, &t[f + 1], 255, &value))
					return VAU_INVALID;

				c.force = (uint8_t)value;
			} else {
				return VAU_INVALID;
			}

			if (seen & bit)
				return VAU_INVALID;

			seen |= bit;
		}

		if ((seen & 7) != 7)
			return VAU_INVALID;

		for (unsigned j = 0; j < out->count[port]; ++j)
			if (out->contacts[port][j].id == c.id)
				return VAU_INVALID;
		out->contacts[port][out->count[port]++] = c;
	}

	return VAU_OK;
}

int vau_input_events_parse(const char *json, const struct vau_json_token *t, size_t array,
                           struct vau_command *out)
{
	if (t[array].type != VAU_JSON_ARRAY)
		return VAU_INVALID;

	struct vau_json_token container = t[array], element[160];
	size_t position                 = container.begin + 1, token_count;
	int readable                    = -1, next;
	VauPad pad                      = { .lx = 128, .ly = 128, .rx = 128, .ry = 128 };
	VauTouchState touch             = { 0 };
	unsigned grouped                = 0;

	while ((next = vau_json_array_next(json, &container, &position, element, 160, &token_count)) >
	       0) {
		t = element;

		size_t i = 0;

		if (readable < 0) {
			readable            = t[0].type == VAU_JSON_OBJECT;
			out->readable_input = (unsigned)readable;
		}

		unsigned at = 0, seen = 0;

		if (!readable) {
			if (t[i].type != VAU_JSON_ARRAY || t[i].next != i + 7 ||
			    out->sequence.count == VAU_MAX_EVENTS) {
				return VAU_INVALID;
			}

			unsigned values[6];

			for (unsigned j = 0; j < 6; ++j)
				if (number(json, &t[i + 1 + j], j < 2 ? UINT32_MAX : 255, &values[j]))
					return VAU_INVALID;
			at  = values[0];
			pad = (VauPad){ values[1], (uint8_t)values[2], (uint8_t)values[3], (uint8_t)values[4],
				            (uint8_t)values[5] };
			if (pad.buttons & ~VAU_BUTTON_MASK)
				return VAU_INVALID;
		} else {
			if (t[i].type != VAU_JSON_OBJECT)
				return VAU_INVALID;

			for (size_t f = i + 1; f < t[i].next; f = t[f + 1].next) {
				char key[24];
				unsigned bit;

				if (vau_json_ascii(json, &t[f], key, sizeof(key)))
					return VAU_INVALID;
				if (!strcmp(key, "at_us")) {
					bit = 1;
					if (number(json, &t[f + 1], UINT32_MAX, &at))
						return VAU_INVALID;
				} else if (!strcmp(key, "buttons")) {
					bit = 2;
					if (pad_buttons(json, t, f + 1, &pad.buttons))
						return VAU_INVALID;
				} else if (!strcmp(key, "left_stick")) {
					bit = 4;
					if (stick(json, t, f + 1, &pad.lx, &pad.ly))
						return VAU_INVALID;
				} else if (!strcmp(key, "right_stick")) {
					bit = 8;
					if (stick(json, t, f + 1, &pad.rx, &pad.ry))
						return VAU_INVALID;
				} else if (!strcmp(key, "front")) {
					bit = 16;
					if (contacts(json, t, f + 1, 0, &touch))
						return VAU_INVALID;

					out->has_touch = 1;
				} else if (!strcmp(key, "back")) {
					bit = 32;
					if (contacts(json, t, f + 1, 1, &touch))
						return VAU_INVALID;

					out->has_touch = 1;
				} else {
					return VAU_INVALID;
				}

				if (seen & bit)
					return VAU_INVALID;

				seen |= bit;
			}

			if (!(seen & 1) || seen == 1)
				return VAU_INVALID;
		}

		unsigned n = out->sequence.count;

		if (!n && at)
			return VAU_INVALID;
		if (n && at < out->last_at_us)
			return VAU_INVALID;
		if (n && at == out->last_at_us) {
			if (!readable || (grouped & (seen & ~1u)))
				return VAU_INVALID;

			grouped |= seen & ~1u;
			--n;
		} else {
			if (n == VAU_MAX_EVENTS)
				return VAU_INVALID;

			++out->sequence.count;
			grouped = seen & ~1u;
		}

		VauEvent event = { at, pad };
		int rc         = vau_input_stream_put(&out->stream, VAU_STAGE_EVENTS, n, &event);

		if (rc >= 0 && readable)
			rc = vau_input_stream_put(&out->stream, VAU_STAGE_TOUCH, n, &touch);
		if (rc < 0)
			return rc;

		out->last_at_us = at;
	}

	return next < 0 || readable < 0 ? VAU_INVALID : VAU_OK;
}
