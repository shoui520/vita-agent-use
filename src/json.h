/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_JSON_H
#define VAU_JSON_H

#include <stddef.h>
#include <stdint.h>

enum vau_json_type {
	VAU_JSON_OBJECT,
	VAU_JSON_ARRAY,
	VAU_JSON_STRING,
	VAU_JSON_NUMBER,
	VAU_JSON_TRUE,
	VAU_JSON_FALSE,
	VAU_JSON_NULL
};

struct vau_json_token {
	size_t begin, end, next;
	enum vau_json_type type;
};

/* Caller owns both input and tokens. No allocation; depth capped at 16.
 * next skips an entire subtree. String offsets exclude the quotes. */
int vau_json_parse(const char *input, size_t length, struct vau_json_token *tokens, size_t capacity,
                   size_t *count);

/* Validate the whole command, but retain no children of arrays at depth two
 * (args.events/args.touch). Decode those arrays one element at a time below. */
int vau_json_parse_command(const char *, size_t, struct vau_json_token *, size_t, size_t *);

/* position starts at array.begin+1. Returns 1 for an element, 0 at the end,
 * or -1 on error. Element token offsets remain relative to the original JSON. */
int vau_json_array_next(const char *, const struct vau_json_token *, size_t *,
                        struct vau_json_token *, size_t, size_t *);

/* Decode only ASCII strings, for protocol keys, operations and identifiers.
 * UTF-8/non-ASCII Unicode strings are valid JSON but rejected by this getter. */
int vau_json_ascii(const char *input, const struct vau_json_token *token, char *output,
                   size_t capacity);

/* Decode a parsed JSON string to UTF-8, including Unicode escapes. No NULs. */
int vau_json_utf8(const char *input, const struct vau_json_token *token, char *output,
                  size_t capacity);

/* Encode a NUL-terminated UTF-8 string, including quotes; reject invalid UTF-8. */
int vau_json_quote(const char *input, char *output, size_t capacity);
int vau_json_u64(const char *input, const struct vau_json_token *token, uint64_t *value);

#endif
