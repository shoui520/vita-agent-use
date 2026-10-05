/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "json.h"
#include <string.h>

struct parser {
	const unsigned char *s;
	size_t len, pos, count, cap;
	struct vau_json_token *tokens;
	unsigned skip, command;
};

static void space(struct parser *p)
{
	while (p->pos < p->len && (p->s[p->pos] == ' ' || p->s[p->pos] == '\t' ||
	                           p->s[p->pos] == '\r' || p->s[p->pos] == '\n')) {
		++p->pos;
	}
}

static int hex(unsigned char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int codeunit(struct parser *p, unsigned *v)
{
	if (p->len - p->pos < 4)
		return -1;

	*v = 0;
	for (int i = 0; i < 4; ++i) {
		int n = hex(p->s[p->pos++]);

		if (n < 0)
			return -1;

		*v = (*v << 4) | (unsigned)n;
	}

	return 0;
}

static int string(struct parser *p)
{
	++p->pos;
	while (p->pos < p->len) {
		unsigned c = p->s[p->pos++];

		if (c == '"')
			return 0;
		if (c < 32)
			return -1;
		if (c == '\\') {
			if (p->pos == p->len)
				return -1;

			c = p->s[p->pos++];
			if (c == 'u') {
				if (codeunit(p, &c))
					return -1;
				if (c >= 0xdc00 && c <= 0xdfff)
					return -1;
				if (c >= 0xd800 && c <= 0xdbff) {
					if (p->len - p->pos < 2 || p->s[p->pos++] != '\\' || p->s[p->pos++] != 'u' ||
					    codeunit(p, &c) || c < 0xdc00 || c > 0xdfff) {
						return -1;
					}
				}
			} else if (!strchr("\"\\/bfnrt", (int)c) || !c) {
				return -1;
			}
		} else if (c >= 128) {
			unsigned n, value, minimum;

			if (c >= 0xc2 && c <= 0xdf) {
				n       = 1;
				value   = c & 31;
				minimum = 0x80;
			} else if (c >= 0xe0 && c <= 0xef) {
				n       = 2;
				value   = c & 15;
				minimum = 0x800;
			} else if (c >= 0xf0 && c <= 0xf4) {
				n       = 3;
				value   = c & 7;
				minimum = 0x10000;
			} else {
				return -1;
			}

			if (p->len - p->pos < n)
				return -1;

			while (n--) {
				c = p->s[p->pos++];
				if ((c & 0xc0) != 0x80)
					return -1;

				value = (value << 6) | (c & 63);
			}

			if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
				return -1;
		}
	}

	return -1;
}

static int digit(unsigned c)
{
	return c >= '0' && c <= '9';
}

static int number(struct parser *p)
{
	if (p->s[p->pos] == '-')
		++p->pos;
	if (p->pos == p->len)
		return -1;
	if (p->s[p->pos] == '0') {
		++p->pos;
	} else {
		if (!digit(p->s[p->pos]))
			return -1;

		while (p->pos < p->len && digit(p->s[p->pos]))
			++p->pos;
	}

	if (p->pos < p->len && p->s[p->pos] == '.') {
		++p->pos;
		if (p->pos == p->len || !digit(p->s[p->pos]))
			return -1;

		while (p->pos < p->len && digit(p->s[p->pos]))
			++p->pos;
	}

	if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E')) {
		++p->pos;
		if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-'))
			++p->pos;
		if (p->pos == p->len || !digit(p->s[p->pos]))
			return -1;

		while (p->pos < p->len && digit(p->s[p->pos]))
			++p->pos;
	}

	return 0;
}

static int value(struct parser *p, unsigned depth)
{
	space(p);
	if (depth > 16 || p->pos == p->len || (!p->skip && p->count == p->cap))
		return -1;

	struct vau_json_token ignored;
	struct vau_json_token *t = p->skip ? &ignored : &p->tokens[p->count++];

	t->begin = p->pos;

	unsigned c = p->s[p->pos];

	if (c == '{' || c == '[') {
		int object = c == '{';

		t->type = object ? VAU_JSON_OBJECT : VAU_JSON_ARRAY;

		unsigned close      = object ? '}' : ']';
		unsigned saved_skip = p->skip;

		if (p->command && depth == 2 && !object)
			p->skip = 1;
		++p->pos;
		space(p);
		if (p->pos < p->len && p->s[p->pos] == close) {
			++p->pos;
		} else {
			for (;;) {
				space(p);
				if (object) {
					if (p->pos == p->len || p->s[p->pos] != '"' || value(p, depth + 1))
						return -1;

					space(p);
					if (p->pos == p->len || p->s[p->pos++] != ':')
						return -1;
				}

				if (value(p, depth + 1))
					return -1;

				space(p);
				if (p->pos == p->len)
					return -1;

				c = p->s[p->pos++];
				if (c == close)
					break;
				if (c != ',')
					return -1;
			}
		}

		p->skip = saved_skip;
	} else if (c == '"') {
		t->type = VAU_JSON_STRING;
		++t->begin;
		if (string(p))
			return -1;
	} else if (c == '-' || digit(c)) {
		t->type = VAU_JSON_NUMBER;
		if (number(p))
			return -1;
	} else {
		const char *literal;

		if (c == 't') {
			literal = "true";
			t->type = VAU_JSON_TRUE;
		} else if (c == 'f') {
			literal = "false";
			t->type = VAU_JSON_FALSE;
		} else if (c == 'n') {
			literal = "null";
			t->type = VAU_JSON_NULL;
		} else {
			return -1;
		}

		size_t n = strlen(literal);

		if (p->len - p->pos < n || memcmp(p->s + p->pos, literal, n))
			return -1;

		p->pos += n;
	}

	t->end  = p->pos - (t->type == VAU_JSON_STRING);
	t->next = p->count;
	return 0;
}

static int parse_document(const char *input, size_t length, struct vau_json_token *tokens,
                          size_t capacity, size_t *count, unsigned command)
{
	if (count)
		*count = 0;
	if (!input || !tokens || !capacity || !count)
		return -1;

	struct parser p = { (const unsigned char *)input, length, 0, 0, capacity, tokens, 0, command };

	if (value(&p, 0))
		return -1;

	space(&p);
	if (p.pos != length)
		return -1;

	*count = p.count;
	return 0;
}

int vau_json_parse(const char *input, size_t length, struct vau_json_token *tokens, size_t capacity,
                   size_t *count)
{
	return parse_document(input, length, tokens, capacity, count, 0);
}

int vau_json_parse_command(const char *input, size_t length, struct vau_json_token *tokens,
                           size_t capacity, size_t *count)
{
	return parse_document(input, length, tokens, capacity, count, 1);
}

int vau_json_array_next(const char *input, const struct vau_json_token *array, size_t *position,
                        struct vau_json_token *tokens, size_t capacity, size_t *count)
{
	if (count)
		*count = 0;
	if (!input || !array || !position || !tokens || !capacity || !count ||
	    array->type != VAU_JSON_ARRAY || array->end <= array->begin + 1 ||
	    *position <= array->begin || *position >= array->end || input[array->begin] != '[' ||
	    input[array->end - 1] != ']') {
		return -1;
	}

	struct parser p = {
		(const unsigned char *)input, array->end - 1, *position, 0, capacity, tokens, 0, 0
	};

	space(&p);
	if (p.pos == p.len) {
		*position = p.pos;
		return 0;
	}

	if (value(&p, 0))
		return -1;

	space(&p);
	if (p.pos < p.len) {
		if (p.s[p.pos++] != ',')
			return -1;

		space(&p);
		if (p.pos == p.len)
			return -1;
	}

	*position = p.pos;
	*count    = p.count;
	return 1;
}

int vau_json_ascii(const char *input, const struct vau_json_token *t, char *output, size_t capacity)
{
	if (!input || !t || !output || !capacity || t->type != VAU_JSON_STRING)
		return -1;

	size_t n = 0;

	for (size_t i = t->begin; i < t->end; ++i) {
		unsigned c = (unsigned char)input[i];

		if (c == '\\') {
			if (++i == t->end)
				return -1;

			c = (unsigned char)input[i];
			if (c == 'u') {
				if (t->end - i < 5)
					return -1;

				c = 0;
				for (int j = 0; j < 4; ++j) {
					int h = hex((unsigned char)input[++i]);

					if (h < 0)
						return -1;

					c = (c << 4) | (unsigned)h;
				}
			} else {
				const char *codes = "\"\\/bfnrt", *decoded = "\"\\/\b\f\n\r\t";
				const char *at = strchr(codes, (int)c);

				if (!at || !c)
					return -1;

				c = (unsigned char)decoded[at - codes];
			}
		}

		if (!c || c > 127 || n + 1 >= capacity)
			return -1;

		output[n++] = (char)c;
	}

	output[n] = 0;
	return 0;
}

int vau_json_utf8(const char *input, const struct vau_json_token *t, char *out, size_t capacity)
{
	if (!input || !t || !out || !capacity || t->type != VAU_JSON_STRING)
		return -1;

	size_t n        = 0;
	struct parser p = { .s = (const unsigned char *)input, .pos = t->begin, .len = t->end };

	while (p.pos < p.len) {
		unsigned c = p.s[p.pos++];

		if (c != '\\') {
			if (!c || n + 1 >= capacity)
				return -1;

			out[n++] = (char)c;
			continue;
		}

		if (p.pos == p.len)
			return -1;

		c = p.s[p.pos++];
		if (c == 'u') {
			if (codeunit(&p, &c))
				return -1;
			if (c >= 0xd800 && c <= 0xdbff) {
				unsigned low;

				if (p.len - p.pos < 2 || p.s[p.pos++] != '\\' || p.s[p.pos++] != 'u' ||
				    codeunit(&p, &low) || low < 0xdc00 || low > 0xdfff) {
					return -1;
				}

				c = 0x10000 + ((c - 0xd800) << 10) + (low - 0xdc00);
			} else if (c >= 0xdc00 && c <= 0xdfff) {
				return -1;
			}
		} else {
			const char *codes = "\"\\/bfnrt", *decoded = "\"\\/\b\f\n\r\t";
			const char *at = strchr(codes, (int)c);

			if (!c || !at)
				return -1;

			c = (unsigned char)decoded[at - codes];
		}

		if (!c)
			return -1;

		unsigned bytes = c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;

		if (n + bytes >= capacity)
			return -1;
		if (bytes == 1) {
			out[n++] = (char)c;
		} else {
			out[n++] = (char)((bytes == 2   ? 0xc0
			                   : bytes == 3 ? 0xe0
			                                : 0xf0) |
			                  (c >> (6 * (bytes - 1))));
			for (unsigned remaining = bytes - 1; remaining; --remaining)
				out[n++] = (char)(0x80 | ((c >> (6 * (remaining - 1))) & 63));
		}
	}

	out[n] = 0;
	return 0;
}

int vau_json_u64(const char *input, const struct vau_json_token *t, uint64_t *out)
{
	if (!input || !t || !out || t->type != VAU_JSON_NUMBER || t->end == t->begin)
		return -1;

	uint64_t n = 0;

	for (size_t i = t->begin; i < t->end; ++i) {
		unsigned c = (unsigned char)input[i];

		if (!digit(c) || n > (UINT64_MAX - (c - '0')) / 10)
			return -1;

		n = n * 10 + c - '0';
	}

	*out = n;
	return 0;
}

int vau_json_quote(const char *input, char *output, size_t capacity)
{
	if (!input || !output || capacity < 3)
		return -1;

	static const char digits[] = "0123456789abcdef";
	size_t used                = 0;

	output[used++] = '"';
	for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
		unsigned c  = *p;
		size_t need = c < 32 ? 6u : c == '"' || c == '\\' ? 2u : 1u;

		if (need > capacity - used - 2)
			return -1;
		if (c < 32) {
			output[used++] = '\\';
			output[used++] = 'u';
			output[used++] = '0';
			output[used++] = '0';
			output[used++] = digits[c >> 4];
			output[used++] = digits[c & 15];
		} else {
			if (need == 2)
				output[used++] = '\\';
			output[used++] = (char)c;
		}
	}

	output[used++] = '"';
	output[used]   = 0;

	struct vau_json_token token[1];
	size_t count;

	return vau_json_parse(output, used, token, 1, &count) ? -1 : (int)used;
}
