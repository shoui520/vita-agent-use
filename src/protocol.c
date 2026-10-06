/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "format.h"
#include "protocol.h"
#include "upload_wire.h"
#include "json.h"
#include "input_sequence.h"
#include "sha256.h"
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

/*
 * Adding an operation takes three edits that nothing checks at compile time:
 * this enum, operations[] below (same index), and the "operations" list in the
 * capabilities reply. Range checks such as OP_RUN_BEGIN..OP_RUN_STATUS also
 * depend on the order here.
 */
enum {
	OP_CAPABILITIES,
	OP_SNAPSHOT,
	OP_LAUNCH,
	OP_CLOSE,
	OP_SCREEN_ON,
	OP_SCREEN_OFF,
	OP_INPUT_ACQUIRE,
	OP_INPUT_HEARTBEAT,
	OP_INPUT_CANCEL,
	OP_INPUT_RELEASE,
	OP_INPUT_STATUS,
	OP_INPUT_SUBMIT,
	OP_FILE_STAT,
	OP_FILE_LIST,
	OP_TOUCH_PANELS,
	OP_REBOOT,
	OP_APP_LIST,
	OP_FILE_MKDIR,
	OP_FILE_MOVE,
	OP_FILE_TRASH,
	OP_FILE_PURGE,
	OP_ACL_REQUEST,
	OP_ACL_STATUS,
	OP_ACL_AUDIT,
	OP_MACRO_ACQUIRE,
	OP_PLUGIN_LIST,
	OP_PERF_MEASURE,
	OP_PERF_WATCH,
	OP_PERF_READ,
	OP_PERF_CANCEL,
	OP_APP_RUNNING,
	OP_EVENTS_START,
	OP_EVENTS_READ,
	OP_EVENTS_STOP,
	OP_LIVEAREA_SCHEMA,
	OP_LOG_START,
	OP_LOG_READ,
	OP_LOG_STOP,
	OP_CONTENT_LIST,
	OP_LIVEAREA_LAYOUT,
	OP_LIVEAREA_BLOB,
	OP_DIALOG_START,
	OP_DIALOG_READ,
	OP_DIALOG_STOP,
	OP_MACRO_ENQUEUE,
	OP_CONTENT_STATUS,
	OP_CONTENT_CHANGES,
	OP_CONTENT_AUDIT,
	OP_CONTENT_PREVIEW,
	OP_CONTENT_SCOPE,
	OP_CONTENT_REQUEST,
	OP_CONTENT_ALBUMS,
	OP_INSTALL,
	OP_INSTALL_STATUS,
	OP_SUBSCRIBE,
	OP_RUN_BEGIN,
	OP_RUN_UPDATE,
	OP_RUN_END,
	OP_RUN_STATUS
};

static const char *const operations[] = {
	"capabilities",
	"system.snapshot",
	"app.launch",
	"app.close",
	"screen.on",
	"screen.off",
	"input.acquire",
	"input.heartbeat",
	"input.cancel",
	"input.release",
	"input.status",
	"input.submit",
	"fs.stat",
	"fs.list",
	"touch.panels",
	"system.reboot",
	"app.list",
	"fs.mkdir",
	"fs.move",
	"fs.trash",
	"fs.purge",
	"acl.request",
	"acl.status",
	"acl.audit",
	"macro.acquire",
	"plugins.list",
	"performance.measure",
	"performance.watch",
	"performance.read",
	"performance.cancel",
	"app.running",
	"events.start",
	"events.read",
	"events.stop",
	"livearea.schema",
	"log.start",
	"log.read",
	"log.stop",
	"content.list",
	"livearea.layout",
	"livearea.blob",
	"dialog.events.start",
	"dialog.events.read",
	"dialog.events.stop",
	"macro.enqueue",
	"content.delete.status",
	"content.delete.changes",
	"content.audit",
	"content.delete.preview",
	"content.scope",
	"content.delete.request",
	"content.albums",
	"app.install",
	"app.install.status",
	"events.subscribe",
	"run.begin",
	"run.update",
	"run.end",
	"run.status",
};

void vau_session_init(struct vau_session *s, unsigned rights)
{
	memset(s, 0, sizeof(*s));
	s->rights = rights & (VAU_RIGHT_OBSERVE | VAU_RIGHT_CONTROL);
}

static int parse_touch(const char *json, const struct vau_json_token *t, size_t array,
                       struct vau_command *out, uint32_t *count)
{
	if (t[array].type != VAU_JSON_ARRAY)
		return VAU_INVALID;

	struct vau_json_token container = t[array], element[64];
	size_t position                 = container.begin + 1, token_count;
	int next;

	while ((next = vau_json_array_next(json, &container, &position, element, 64, &token_count)) >
	       0) {
		t = element;

		size_t state = 0;

		if (*count >= VAU_MAX_EVENTS || t[state].type != VAU_JSON_ARRAY)
			return VAU_INVALID;

		VauTouchState *touch = &out->touch[(*count)++];

		memset(touch, 0, sizeof(*touch));

		uint64_t enabled;
		size_t field = state + 1;

		if (field >= t[state].next || vau_json_u64(json, &t[field], &enabled) || enabled > 3)
			return VAU_INVALID;

		touch->enabled = (uint8_t)enabled;
		field          = t[field].next;
		for (unsigned port = 0; port < 2; port++) {
			if (field >= t[state].next || t[field].type != VAU_JSON_ARRAY)
				return VAU_INVALID;

			for (size_t contact = field + 1; contact < t[field].next; contact = t[contact].next) {
				unsigned n = touch->count[port];

				if (n >= (port ? 4u : 6u) || t[contact].type != VAU_JSON_ARRAY ||
				    t[contact].next != contact + 5) {
					return VAU_INVALID;
				}

				uint64_t values[4];

				for (unsigned j = 0; j < 4; j++) {
					if (vau_json_u64(json, &t[contact + 1 + j], &values[j]) ||
					    values[j] > (j == 0   ? 127u
					                 : j == 1 ? 255u
					                          : 32767u)) {
						return VAU_INVALID;
					}
				}

				for (unsigned j = 0; j < n; j++)
					if (touch->contacts[port][j].id == values[0])
						return VAU_INVALID;
				touch->contacts[port][n] =
				        (VauTouchContact){ (uint8_t)values[0], (uint8_t)values[1],
					                       (int16_t)values[2], (int16_t)values[3], 0 };
				touch->count[port]++;
			}

			if (!(enabled & (1u << port)) && touch->count[port])
				return VAU_INVALID;

			field = t[field].next;
		}

		if (field != t[state].next)
			return VAU_INVALID;
	}

	return next < 0 ? VAU_INVALID : VAU_OK;
}

static int parse_sequence(const char *json, const struct vau_json_token *t, size_t args,
                          struct vau_command *out)
{
	VauSequence *s = &out->sequence;

	s->size = sizeof(*s);
	s->abi  = VAU_ABI;

	unsigned seen        = 0;
	uint32_t touch_count = 0;

	for (size_t i = args + 1; i < t[args].next;) {
		char key[24];
		unsigned bit;
		uint64_t n;
		size_t v = i + 1;

		if (vau_json_ascii(json, &t[i], key, sizeof(key)))
			return VAU_INVALID;
		if (!strcmp(key, "events")) {
			bit = 16;
			if (t[v].type != VAU_JSON_ARRAY)
				return VAU_INVALID;
			if (vau_input_events_parse(json, t, v, out) < 0)
				return VAU_INVALID;
		} else if (!strcmp(key, "touch")) {
			bit            = 32;
			out->has_touch = 1;
			if (parse_touch(json, t, v, out, &touch_count) < 0)
				return VAU_INVALID;
		} else if (!strcmp(key, "start_delay_us")) {
			bit = 1;

			uint64_t delay;

			if (vau_json_u64(json, &t[v], &delay) || delay < 10000 || delay > 1000000)
				return VAU_INVALID;

			out->start_delay_us = (uint32_t)delay;
		} else if (!strcmp(key, "start_us")) {
			char text[21];

			bit = 1;
			if (vau_json_ascii(json, &t[v], text, sizeof(text)) || !text[0] ||
			    (text[0] == '0' && text[1])) {
				return VAU_INVALID;
			}

			struct vau_json_token digits = { 0, strlen(text), 0, VAU_JSON_NUMBER };

			if (vau_json_u64(text, &digits, &s->start_us))
				return VAU_INVALID;
		} else {
			if (vau_json_u64(json, &t[v], &n) || n > UINT32_MAX)
				return VAU_INVALID;
			if (!strcmp(key, "duration_us")) {
				bit            = 2;
				s->duration_us = (uint32_t)n;
			} else if (!strcmp(key, "repeats")) {
				bit        = 4;
				s->repeats = (uint32_t)n;
			} else if (!strcmp(key, "max_lateness_us")) {
				bit                = 8;
				s->max_lateness_us = (uint32_t)n;
			} else {
				return VAU_INVALID;
			}
		}

		if (seen & bit)
			return VAU_INVALID;

		seen |= bit;
		i = t[v].next;
	}

	if ((seen != 31u && seen != 63u) ||
	    ((seen & 32u) && (out->readable_input || touch_count != s->count)) || !s->count ||
	    !s->duration_us || s->duration_us > VAU_MAX_DURATION_US || !s->repeats ||
	    s->repeats > VAU_MAX_REPEATS || !s->max_lateness_us || s->max_lateness_us > 1000000u ||
	    out->events[s->count - 1].at_us >= s->duration_us ||
	    s->start_us > UINT64_MAX - (uint64_t)s->duration_us * s->repeats) {
		return VAU_INVALID;
	}

	return VAU_OK;
}

static int content_counter(const char *json, const struct vau_json_token *token, uint64_t *out)
{
	char text[21];

	if (vau_json_ascii(json, token, text, sizeof(text)) || !text[0] || (text[0] == '0' && text[1]))
		return VAU_INVALID;

	struct vau_json_token number = { 0, strlen(text), 0, VAU_JSON_NUMBER };

	return vau_json_u64(text, &number, out) || *out > INT64_MAX ? VAU_INVALID : VAU_OK;
}

static int parse(const char *json, size_t length, struct vau_command *out, struct vau_json_token *t)
{
	size_t count;
	unsigned seen = 0;
	size_t args   = 0;

	memset(out, 0, offsetof(struct vau_command, touch));
	if (length > VAU_REQUEST_BYTES ||
	    vau_json_parse_command(json, length, t, VAU_COMMAND_TOKENS, &count) ||
	    t[0].type != VAU_JSON_OBJECT) {
		return VAU_INVALID;
	}

	for (size_t i = 1; i < count;) {
		char key[16];

		if (vau_json_ascii(json, &t[i], key, sizeof(key)))
			return VAU_INVALID;

		size_t v = i + 1;
		unsigned bit;

		if (!strcmp(key, "v")) {
			uint64_t version;

			bit = 1;
			if (vau_json_u64(json, &t[v], &version) || version != 1)
				return VAU_INVALID;
		} else if (!strcmp(key, "id")) {
			char id[21];

			bit = 2;
			if (vau_json_ascii(json, &t[v], id, sizeof(id)) || id[0] < '1' || id[0] > '9')
				return VAU_INVALID;

			struct vau_json_token digits = { 0, strlen(id), 0, VAU_JSON_NUMBER };

			if (vau_json_u64(id, &digits, &out->id))
				return VAU_INVALID;
		} else if (!strcmp(key, "op")) {
			char op[32];

			bit = 4;
			if (vau_json_ascii(json, &t[v], op, sizeof(op)))
				return VAU_INVALID;

			unsigned n;

			for (n = 0; n < sizeof(operations) / sizeof(*operations); ++n)
				if (!strcmp(op, operations[n]))
					break;
			if (n == sizeof(operations) / sizeof(*operations))
				return VAU_UNSUPPORTED;

			out->operation = n;
		} else if (!strcmp(key, "args")) {
			bit  = 8;
			args = v;
			if (t[v].type != VAU_JSON_OBJECT)
				return VAU_INVALID;
		} else {
			return VAU_INVALID;
		}

		if (seen & bit)
			return VAU_INVALID;

		seen |= bit;
		i = t[v].next;
	}

	if (seen != 15)
		return VAU_INVALID;
	if (out->operation == OP_SUBSCRIBE || out->operation == OP_RUN_STATUS)
		return t[args].next == args + 1 ? VAU_OK : VAU_INVALID;
	if (out->operation >= OP_RUN_BEGIN && out->operation <= OP_RUN_END) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[24];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "run_id")) {
				bit = 1;
				if (vau_json_ascii(json, &t[i + 1], out->mutation_id, sizeof(out->mutation_id)) ||
				    strlen(out->mutation_id) != 32) {
					return VAU_INVALID;
				}

				for (unsigned j = 0; j < 32; j++)
					if (!strchr("0123456789abcdef", out->mutation_id[j]))
						return VAU_INVALID;
			} else if (!strcmp(key, "title_id") && out->operation == OP_RUN_BEGIN) {
				bit = 2;
				if (vau_json_ascii(json, &t[i + 1], out->title, sizeof(out->title)) ||
				    !vau_title_valid(out->title)) {
					return VAU_INVALID;
				}
			} else if (!strcmp(key, "phase") && out->operation != OP_RUN_BEGIN) {
				bit = 2;
				if (vau_json_ascii(json, &t[i + 1], out->content_category, 24))
					return VAU_INVALID;

				const char *phases[] = {
					"preparing", "armed",     "launching", "running",         "closing",
					"completed", "cancelled", "failed",    "connection_lost",
				};
				unsigned j;

				for (j = 0; j < sizeof(phases) / sizeof(*phases); j++)
					if (!strcmp(phases[j], out->content_category))
						break;
				if (j == sizeof(phases) / sizeof(*phases))
					return VAU_INVALID;
				if ((out->operation == OP_RUN_END && j < 5) ||
				    (out->operation == OP_RUN_UPDATE && j >= 5)) {
					return VAU_INVALID;
				}
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return found == 3 ? VAU_OK : VAU_INVALID;
	}

	if (out->operation == OP_INSTALL || out->operation == OP_INSTALL_STATUS) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[24];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "operation_id")) {
				bit = 1;
				if (vau_json_ascii(json, &t[i + 1], out->mutation_id, sizeof(out->mutation_id)) ||
				    strlen(out->mutation_id) != 32) {
					return VAU_INVALID;
				}

				for (unsigned j = 0; j < 32; j++)
					if (!strchr("0123456789abcdef", out->mutation_id[j]))
						return VAU_INVALID;
			} else if (!strcmp(key, "path") && out->operation == OP_INSTALL) {
				bit = 2;
				if (vau_json_utf8(json, &t[i + 1], out->path, sizeof(out->path)) || !out->path[0])
					return VAU_INVALID;

				char normalized[VAU_PATH_MAX];
				size_t n = strlen(out->path);

				if (n < 5 || strcmp(out->path + n - 4, ".vpk") ||
				    vau_path_normalize(out->path, normalized, sizeof(normalized)) ||
				    strcmp(normalized, out->path)) {
					return VAU_INVALID;
				}
			} else if (!strcmp(key, "yes") && out->operation == OP_INSTALL) {
				bit = 4;
				if (t[i + 1].type != VAU_JSON_TRUE)
					return VAU_DENIED;

				out->yes = 1;
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return found == (out->operation == OP_INSTALL ? 7u : 1u) ? VAU_OK : VAU_INVALID;
	}

	if (out->operation >= OP_CONTENT_STATUS && out->operation <= OP_CONTENT_ALBUMS) {
		unsigned found    = 0;
		unsigned required = out->operation == OP_CONTENT_STATUS    ? 1u
		                    : out->operation == OP_CONTENT_CHANGES ? 29u
		                    : out->operation == OP_CONTENT_AUDIT   ? 16u
		                    : out->operation == OP_CONTENT_ALBUMS  ? 29u
		                    : out->operation == OP_CONTENT_SCOPE   ? 21u
		                    : out->operation == OP_CONTENT_REQUEST ? 39u
		                                                           : 1u;
		unsigned optional = out->operation == OP_CONTENT_PREVIEW   ? 450u
		                    : out->operation == OP_CONTENT_REQUEST ? 192u
		                                                           : 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[24];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "operation_id")) {
				bit = 1;
				if (vau_json_ascii(json, &t[i + 1], out->mutation_id, sizeof(out->mutation_id)) ||
				    strlen(out->mutation_id) != 32) {
					return VAU_INVALID;
				}

				for (unsigned j = 0; j < 32; j++)
					if (!strchr("0123456789abcdef", out->mutation_id[j]))
						return VAU_INVALID;
			} else if (!strcmp(key, "title_id")) {
				bit = 2;
				if (vau_json_ascii(json, &t[i + 1], out->title, sizeof(out->title)) ||
				    !vau_title_valid(out->title) || !strncmp(out->title, "NPXS", 4)) {
					return VAU_INVALID;
				}
			} else if ((!strcmp(key, "before_scope") && out->operation == OP_CONTENT_CHANGES) ||
			           (!strcmp(key, "scope_sequence") && (out->operation == OP_CONTENT_SCOPE ||
			                                               out->operation == OP_CONTENT_ALBUMS))) {
				bit = 4;
				if (content_counter(json, &t[i + 1], &out->content_before) || !out->content_before)
					return VAU_INVALID;
			} else if (!strcmp(key, "preview_scope") && out->operation == OP_CONTENT_REQUEST) {
				bit = 4;
				if (content_counter(json, &t[i + 1], &out->content_before) || !out->content_before)
					return VAU_INVALID;
			} else if (!strcmp(key, "yes") && out->operation == OP_CONTENT_REQUEST) {
				bit = 32;
				if (t[i + 1].type != VAU_JSON_TRUE)
					return VAU_DENIED;

				out->yes = 1;
			} else if (!strcmp(key, "kind") && optional) {
				char kind[24];

				bit = 64;
				if (vau_json_ascii(json, &t[i + 1], kind, sizeof(kind)))
					return VAU_INVALID;
				if (!strcmp(kind, "vita_savedata"))
					out->content_kind = 1;
				else if (out->operation == OP_CONTENT_PREVIEW && !strcmp(kind, "photo"))
					out->content_kind = 2;
				else if (out->operation == OP_CONTENT_PREVIEW && !strcmp(kind, "music"))
					out->content_kind = 3;
				else if (out->operation == OP_CONTENT_PREVIEW && !strcmp(kind, "video"))
					out->content_kind = 4;
				else if (strcmp(kind, "application"))
					return VAU_UNSUPPORTED;
			} else if (!strcmp(key, "media_id") && out->operation == OP_CONTENT_PREVIEW) {
				bit = 256;
				if (content_counter(json, &t[i + 1], &out->content_media_id) ||
				    !out->content_media_id) {
					return VAU_INVALID;
				}
			} else if (!strcmp(key, "user") && optional) {
				uint64_t user;

				bit = 128;
				if (vau_json_u64(json, &t[i + 1], &user) || user >= 64)
					return VAU_INVALID;

				out->content_user = (unsigned)user;
			} else if ((!strcmp(key, "after_scope") && out->operation == OP_CONTENT_CHANGES) ||
			           (!strcmp(key, "list_cursor") && out->operation == OP_CONTENT_ALBUMS)) {
				bit = 8;
				if (content_counter(json, &t[i + 1], &out->content_after))
					return VAU_INVALID;
			} else if (!strcmp(key, "cursor")) {
				bit = 16;
				if (content_counter(json, &t[i + 1], &out->content_cursor))
					return VAU_INVALID;
			} else {
				return VAU_INVALID;
			}

			if (!((required | optional) & bit) || (found & bit))
				return VAU_INVALID;

			found |= bit;
		}

		if (out->content_kind >= 2) {
			if ((found & 450u) != 320u)
				return VAU_INVALID;
		} else {
			if (out->content_kind ? (found & 192u) != 192u : (found & 128u) != 0)
				return VAU_INVALID;
			if (out->operation == OP_CONTENT_PREVIEW && !(found & 2u))
				return VAU_INVALID;
			if (found & 256u)
				return VAU_INVALID;
		}

		return (found & ~optional) == required ? VAU_OK : VAU_INVALID;
	}

	if (out->operation == OP_FILE_STAT || out->operation == OP_FILE_LIST) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[16];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "path")) {
				char path[VAU_PATH_MAX];

				bit = 1;
				if (vau_json_utf8(json, &t[i + 1], path, sizeof(path)) ||
				    vau_path_normalize(path, out->path, sizeof(out->path))) {
					return VAU_INVALID;
				}
			} else if (!strcmp(key, "offset") && out->operation == OP_FILE_LIST) {
				uint64_t value;

				bit = 2;
				if (vau_json_u64(json, &t[i + 1], &value) || value > VAU_FILE_OFFSET_MAX)
					return VAU_INVALID;

				out->offset = (uint32_t)value;
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return found == (out->operation == OP_FILE_STAT ? 1u : 3u) ? VAU_OK : VAU_INVALID;
	}

	if (out->operation == OP_LIVEAREA_BLOB) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[16];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "section")) {
				bit = 1;
				if (vau_json_ascii(json, &t[i + 1], out->content_category,
				                   sizeof(out->content_category)) ||
				    (strcmp(out->content_category, "icons") &&
				     strcmp(out->content_category, "pages"))) {
					return VAU_INVALID;
				}
			} else if (!strcmp(key, "page_id")) {
				bit = 2;
				if (vau_json_ascii(json, &t[i + 1], out->blob_page, sizeof(out->blob_page)))
					return VAU_INVALID;
			} else if (!strcmp(key, "column")) {
				bit = 4;
				if (vau_json_ascii(json, &t[i + 1], out->blob_column, sizeof(out->blob_column)))
					return VAU_INVALID;
			} else if (!strcmp(key, "position") || !strcmp(key, "offset")) {
				bit = !strcmp(key, "position") ? 8 : 16;

				uint64_t value;

				if (vau_json_u64(json, &t[i + 1], &value) || value > INT32_MAX)
					return VAU_INVALID;
				if (bit == 8)
					out->blob_position = (uint32_t)value;
				else
					out->offset = (uint32_t)value;
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return found == 31u ? VAU_OK : VAU_INVALID;
	}

	if (out->operation == OP_LIVEAREA_LAYOUT) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[16];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "section")) {
				bit = 1;
				if (vau_json_ascii(json, &t[i + 1], out->content_category,
				                   sizeof(out->content_category)) ||
				    (strcmp(out->content_category, "icons") &&
				     strcmp(out->content_category, "pages"))) {
					return VAU_INVALID;
				}
			} else if (!strcmp(key, "offset")) {
				bit = 2;

				uint64_t offset;

				if (vau_json_u64(json, &t[i + 1], &offset) || offset > 100000)
					return VAU_INVALID;

				out->offset = (uint32_t)offset;
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return found == 3u ? VAU_OK : VAU_INVALID;
	}

	if (out->operation >= OP_LOG_START && out->operation <= OP_LOG_STOP) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[16];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (out->operation == OP_LOG_START && !strcmp(key, "path")) {
				char path[VAU_PATH_MAX];

				bit = 1;
				if (vau_json_utf8(json, &t[i + 1], path, sizeof(path)) ||
				    vau_path_normalize(path, out->path, sizeof(out->path))) {
					return VAU_INVALID;
				}
			} else if (out->operation == OP_LOG_START && !strcmp(key, "marker")) {
				bit = 2;
				if (vau_json_utf8(json, &t[i + 1], out->log_marker, sizeof(out->log_marker)) ||
				    !out->log_marker[0]) {
					return VAU_INVALID;
				}
			} else if (out->operation != OP_LOG_START && !strcmp(key, "watch_id")) {
				uint64_t value;

				bit = 1;
				if (vau_json_u64(json, &t[i + 1], &value) || !value || value > UINT32_MAX)
					return VAU_INVALID;

				out->offset = (uint32_t)value;
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return found == (out->operation == OP_LOG_START ? 3u : 1u) ? VAU_OK : VAU_INVALID;
	}

	if (out->operation == OP_EVENTS_READ || out->operation == OP_DIALOG_READ) {
		char key[16];
		uint64_t value;

		if (t[args].next != args + 3 || vau_json_ascii(json, &t[args + 1], key, sizeof(key)) ||
		    strcmp(key, "after") || vau_json_u64(json, &t[args + 2], &value) ||
		    value > UINT32_MAX) {
			return VAU_INVALID;
		}

		out->offset = (uint32_t)value;
		return VAU_OK;
	}

	if (out->operation == OP_PERF_WATCH) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[24];
			uint64_t value;
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)) ||
			    vau_json_u64(json, &t[i + 1], &value)) {
				return VAU_INVALID;
			}

			if (!strcmp(key, "duration_s")) {
				bit = 1;
				if (value < 1 || value > 3600)
					return VAU_INVALID;

				out->offset = (uint32_t)value;
			} else if (!strcmp(key, "interval_ms")) {
				bit = 2;
				if (value < 100 || value > 60000)
					return VAU_INVALID;

				out->start_delay_us = (uint32_t)value;
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return (found & 1) && (!out->start_delay_us || out->start_delay_us <= out->offset * 1000)
		               ? VAU_OK
		               : VAU_INVALID;
	}

	if (out->operation >= OP_PERF_MEASURE && out->operation <= OP_PERF_CANCEL) {
		if (out->operation == OP_PERF_CANCEL)
			return t[args].next == args + 1 ? VAU_OK : VAU_INVALID;

		char key[24];
		uint64_t value;
		const char *expected = out->operation == OP_PERF_MEASURE ? "window_ms"
		                       : out->operation == OP_PERF_WATCH ? "duration_s"
		                                                         : "after";

		if (t[args].next != args + 3 || vau_json_ascii(json, &t[args + 1], key, sizeof(key)) ||
		    strcmp(key, expected) || vau_json_u64(json, &t[args + 2], &value) ||
		    value > UINT32_MAX) {
			return VAU_INVALID;
		}

		if (out->operation == OP_PERF_MEASURE && (value < 100 || value > 60000))
			return VAU_INVALID;
		if (out->operation == OP_PERF_WATCH && (value < 1 || value > 3600))
			return VAU_INVALID;

		out->offset = (uint32_t)value;
		return VAU_OK;
	}

	if (out->operation == OP_ACL_AUDIT || out->operation == OP_PLUGIN_LIST) {
		char key[16];
		uint64_t offset;

		if (t[args].next != args + 3 || vau_json_ascii(json, &t[args + 1], key, sizeof(key)) ||
		    strcmp(key, "offset") || vau_json_u64(json, &t[args + 2], &offset) ||
		    offset > UINT32_MAX - 1024) {
			return VAU_INVALID;
		}

		out->offset = (uint32_t)offset;
		return VAU_OK;
	}

	if (out->operation == OP_ACL_REQUEST || out->operation == OP_ACL_STATUS) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[24];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "request_id")) {
				bit = 1;
				if (vau_json_ascii(json, &t[i + 1], out->mutation_id, sizeof(out->mutation_id)) ||
				    strlen(out->mutation_id) != 32) {
					return VAU_INVALID;
				}

				for (unsigned j = 0; j < 32; ++j)
					if (!strchr("0123456789abcdef", out->mutation_id[j]))
						return VAU_INVALID;
			} else if (!strcmp(key, "path") && out->operation == OP_ACL_REQUEST) {
				char path[VAU_PATH_MAX];

				bit = 2;
				if (vau_json_utf8(json, &t[i + 1], path, sizeof(path)) ||
				    vau_path_normalize(path, out->path, sizeof(out->path))) {
					return VAU_INVALID;
				}
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return found == (out->operation == OP_ACL_REQUEST ? 3u : 1u) ? VAU_OK : VAU_INVALID;
	}

	if (out->operation >= OP_FILE_MKDIR && out->operation <= OP_FILE_PURGE) {
		unsigned found = 0;

		for (size_t i = args + 1; i < t[args].next; i = t[i + 1].next) {
			char key[24];
			unsigned bit;

			if (vau_json_ascii(json, &t[i], key, sizeof(key)))
				return VAU_INVALID;
			if (!strcmp(key, "operation_id")) {
				bit = 1;
				if (vau_json_ascii(json, &t[i + 1], out->mutation_id, sizeof(out->mutation_id)) ||
				    strlen(out->mutation_id) != 32) {
					return VAU_INVALID;
				}

				for (unsigned j = 0; j < 32; ++j)
					if (!strchr("0123456789abcdef", out->mutation_id[j]))
						return VAU_INVALID;
			} else if (!strcmp(key, "path") ||
			           (!strcmp(key, "destination") && out->operation == OP_FILE_MOVE)) {
				char path[VAU_PATH_MAX];

				bit = !strcmp(key, "path") ? 2 : 4;
				if (vau_json_utf8(json, &t[i + 1], path, sizeof(path)) ||
				    vau_path_normalize(path, bit == 2 ? out->path : out->destination,
				                       VAU_PATH_MAX)) {
					return VAU_INVALID;
				}
			} else if (!strcmp(key, "yes")) {
				bit = 8;
				if (t[i + 1].type != VAU_JSON_TRUE && t[i + 1].type != VAU_JSON_FALSE)
					return VAU_INVALID;

				out->yes = t[i + 1].type == VAU_JSON_TRUE;
			} else if (!strcmp(key, "trash_id") && out->operation == OP_FILE_PURGE) {
				bit = 16;
				if (vau_json_ascii(json, &t[i + 1], out->trash_id, sizeof(out->trash_id)) ||
				    strlen(out->trash_id) != 32) {
					return VAU_INVALID;
				}

				for (unsigned j = 0; j < 32; ++j)
					if (!strchr("0123456789abcdef", out->trash_id[j]))
						return VAU_INVALID;
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
		}

		return found == (out->operation == OP_FILE_MOVE    ? 15u
		                 : out->operation == OP_FILE_PURGE ? 27u
		                                                   : 11u)
		               ? VAU_OK
		               : VAU_INVALID;
	}

	if (out->operation == OP_APP_LIST || out->operation == OP_LIVEAREA_SCHEMA ||
	    out->operation == OP_CONTENT_LIST) {
		unsigned found = 0;

		for (size_t item = args + 1; item < t[args].next;) {
			char key[16];

			if (vau_json_ascii(json, &t[item++], key, sizeof(key)))
				return VAU_INVALID;

			unsigned bit;

			if (!strcmp(key, "after")) {
				bit = 1;
				if (vau_json_ascii(json, &t[item], out->app_after, sizeof(out->app_after)))
					return VAU_INVALID;
			} else if (!strcmp(key, "category") && out->operation == OP_CONTENT_LIST) {
				bit = 4;
				if (vau_json_ascii(json, &t[item], out->content_category,
				                   sizeof(out->content_category)) ||
				    (strcmp(out->content_category, "photo") &&
				     strcmp(out->content_category, "music") &&
				     strcmp(out->content_category, "video") &&
				     strcmp(out->content_category, "theme") &&
				     strcmp(out->content_category, "psp_application") &&
				     strcmp(out->content_category, "playstation_application") &&
				     strcmp(out->content_category, "psp_savedata") &&
				     strcmp(out->content_category, "playstation_savedata"))) {
					return VAU_INVALID;
				}
			} else if (!strcmp(key, "query") && out->operation == OP_APP_LIST) {
				bit = 2;
				if (vau_json_utf8(json, &t[item], out->app_query, sizeof(out->app_query)))
					return VAU_INVALID;
			} else {
				return VAU_INVALID;
			}

			if (found & bit)
				return VAU_INVALID;

			found |= bit;
			item = t[item].next;
		}

		return out->operation == OP_CONTENT_LIST && !(found & 4u) ? VAU_INVALID : VAU_OK;
	}

	if (out->operation == OP_INPUT_SUBMIT || out->operation == OP_MACRO_ENQUEUE) {
		int rc = parse_sequence(json, t, args, out);

		return rc < 0 ? rc
		       : out->operation == OP_MACRO_ENQUEUE &&
		                       (out->sequence.start_us || out->start_delay_us)
		               ? VAU_INVALID
		               : VAU_OK;
	}

	if (out->operation == OP_LAUNCH || out->operation == OP_CLOSE ||
	    out->operation == OP_MACRO_ACQUIRE) {
		char key[16];

		if (t[args].next != args + 3 || vau_json_ascii(json, &t[args + 1], key, sizeof(key)) ||
		    strcmp(key, "title_id") ||
		    vau_json_ascii(json, &t[args + 2], out->title, sizeof(out->title)) ||
		    !vau_title_valid(out->title)) {
			return VAU_INVALID;
		}
	} else if (t[args].next != args + 1) {
		return VAU_INVALID;
	}

	return VAU_OK;
}

static int error_reply(char *out, size_t cap, const char *id, int error)
{
	return vau_snprintf(
	        out, cap,
	        "{\"v\":1,\"id\":%s,\"status\":\"error\",\"error\":{\"source\":\"protocol\",\"code\":%d}}",
	        id, error);
}

static int metadata_error_reply(const struct vau_native_api *api, char *out, size_t cap,
                                const char *id, int error)
{
	char detail[256];
	int n = api->metadata_error ? api->metadata_error(api->context, detail, sizeof(detail)) : 0;

	if (n <= 0 || (size_t)n >= sizeof(detail))
		return error_reply(out, cap, id, error);
	return vau_snprintf(
	        out, cap,
	        "{\"v\":1,\"id\":%s,\"status\":\"error\",\"error\":{\"source\":\"native_metadata\",\"code\":%d,\"details\":%s}}",
	        id, error, detail);
}

static const char *metric(int value, char text[24])
{
	if (value < 0)
		return "null";

	vau_snprintf(text, 24, "%d", value);
	return text;
}

static int snapshot_reply(const struct vau_native_api *api, char *out, size_t cap, const char *id)
{
	struct vau_console_snapshot s;

	vau_native_snapshot(api, &s);

	char percent[24], confirm[24], language[24], model[24], version_code[24], version[171],
	        console_id[35], free_bytes[24], total_bytes[24], title[16];

	vau_snprintf(free_bytes, sizeof(free_bytes), "%llu", (unsigned long long)s.free_bytes);
	vau_snprintf(total_bytes, sizeof(total_bytes), "%llu", (unsigned long long)s.total_bytes);
	if (s.foreground.title[0])
		vau_snprintf(title, sizeof(title), "\"%s\"", s.foreground.title);
	else
		memcpy(title, "null", 5);
	if (s.console_id_error < 0) {
		memcpy(console_id, "null", 5);
	} else {
		static const char hex[] = "0123456789abcdef";

		console_id[0] = '"';
		for (unsigned i = 0; i < VAU_CONSOLE_ID_BYTES; i++) {
			console_id[1 + 2 * i] = hex[s.console_id.bytes[i] >> 4];
			console_id[2 + 2 * i] = hex[s.console_id.bytes[i] & 15];
		}

		console_id[33] = '"';
		console_id[34] = 0;
	}

	if (s.firmware_error < 0)
		memcpy(version, "null", 5);
	else
		(void)vau_json_quote(s.firmware.text, version, sizeof(version));
	vau_snprintf(version_code, sizeof(version_code), "%u", s.firmware.version_code);

	const char *kind = "unknown";

	if (s.foreground.kind == VAU_FOREGROUND_NONE)
		kind = "none";
	else if (s.foreground.kind == VAU_FOREGROUND_SHELL)
		kind = "shell";
	else if (s.foreground.kind == VAU_FOREGROUND_APP)
		kind = "app";
	/* SceSystemParamLang order; fixed strings require no allocation. */
	static const char *const language_names[] = {
		"\"Japanese\"",
		"\"English (United States)\"",
		"\"French\"",
		"\"Spanish\"",
		"\"German\"",
		"\"Italian\"",
		"\"Dutch\"",
		"\"Portuguese (Portugal)\"",
		"\"Russian\"",
		"\"Korean\"",
		"\"Chinese (Traditional)\"",
		"\"Chinese (Simplified)\"",
		"\"Finnish\"",
		"\"Swedish\"",
		"\"Danish\"",
		"\"Norwegian\"",
		"\"Polish\"",
		"\"Portuguese (Brazil)\"",
		"\"English (United Kingdom)\"",
		"\"Turkish\"",
	};

	const char *language_name =
	        s.system_language >= 0 && (unsigned)s.system_language <
	                                          sizeof(language_names) / sizeof(language_names[0])
	                ? language_names[s.system_language]
	                : "null";
	int n = vau_snprintf(
	        out, cap,
	        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{"
	        "\"begin_us\":\"%llu\",\"end_us\":\"%llu\","
	        "\"foreground\":{\"kind\":\"%s\",\"title_id\":%s,\"app_id\":%d,\"pid\":%d,\"error_code\":%d},"
	        "\"console_id\":{\"value\":%s,\"error_code\":%d},"
	        "\"model\":{\"family\":%s,\"code\":%s,\"error_code\":%d},"
	        "\"firmware\":{\"reported_version\":%s,\"version_code\":%s,\"may_be_spoofed\":true,\"error_code\":%d},"
	        "\"confirmation_button\":{\"name\":%s,\"mask\":%s,\"error_code\":%d},"
	        "\"system_language\":{\"id\":%s,\"name\":%s,\"error_code\":%d},"
	        "\"system_ui_overlaid\":{\"value\":%s,\"error_code\":%d},"
	        "\"battery_percent\":{\"value\":%s,\"error_code\":%d},"
	        "\"battery_charging\":{\"value\":%s,\"error_code\":%d},"
	        "\"ux0\":{\"free_bytes\":%s,\"total_bytes\":%s,\"error_code\":%d}}}",
	        id, (unsigned long long)s.begin_us, (unsigned long long)s.end_us, kind, title,
	        s.foreground.app_id, s.foreground.pid, s.foreground.error, console_id,
	        s.console_id_error < 0 ? s.console_id_error : 0,
	        s.model < 0          ? "null"
	        : s.model == 0x10000 ? "\"vita\""
	        : s.model == 0x20000 ? "\"vita_tv\""
	                             : "\"unknown\"",
	        metric(s.model, model), s.model < 0 ? s.model : 0, version,
	        s.firmware_error < 0 ? "null" : version_code,
	        s.firmware_error < 0 ? s.firmware_error : 0,
	        s.confirmation_button < 0         ? "null"
	        : s.confirmation_button == 0x4000 ? "\"cross\""
	                                          : "\"circle\"",
	        metric(s.confirmation_button, confirm),
	        s.confirmation_button < 0 ? s.confirmation_button : 0,
	        metric(s.system_language, language), language_name,
	        s.system_language < 0 ? s.system_language : 0,
	        s.system_ui_overlaid < 0 ? "null"
	        : s.system_ui_overlaid   ? "true"
	                                 : "false",
	        s.system_ui_overlaid < 0 ? s.system_ui_overlaid : 0, metric(s.battery_percent, percent),
	        s.battery_percent < 0 ? s.battery_percent : 0,
	        s.battery_charging < 0 ? "null"
	        : s.battery_charging   ? "true"
	                               : "false",
	        s.battery_charging < 0 ? s.battery_charging : 0,
	        s.storage_error < 0 ? "null" : free_bytes, s.storage_error < 0 ? "null" : total_bytes,
	        s.storage_error < 0 ? s.storage_error : 0);

	if (n < 2 || (size_t)n >= cap)
		return -1;

	/* Append without allocating another response-sized scratch buffer. */
	int extra = vau_metadata_json(&s, out + n - 2, cap - (size_t)n + 2);

	return extra < 0 || (size_t)extra >= cap - (size_t)n + 2 ? -1 : n - 2 + extra;
}

static int input_reply(struct vau_session *session, const struct vau_native_api *api, unsigned op,
                       int32_t process, char *out, size_t capacity, const char *id)
{
	VauStatus status = { 0 };
	uint64_t lease   = 0;
	int rc           = process      ? (api->input_acquire_process
	                                           ? api->input_acquire_process(api->input_context, session->handle,
	                                                                        process, &lease)
	                                           : VAU_UNSUPPORTED)
	                   : api->input ? api->input(api->input_context, session->handle,
	                                             (enum vau_input_operation)(op - OP_INPUT_ACQUIRE), &status,
	                                             &lease)
	                                : VAU_UNSUPPORTED;

	if (rc < 0)
		return error_reply(out, capacity, id, rc);
	if (op != OP_INPUT_STATUS) {
		return vau_snprintf(
		        out, capacity,
		        "{\"v\":1,\"id\":%s,\"status\":\"accepted\",\"lease_until_us\":\"%llu\"}", id,
		        (unsigned long long)lease);
	}

	return vau_snprintf(
	        out, capacity,
	        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{"
	        "\"state\":%u,\"error_code\":%d,\"execution_id\":\"%llu\",\"now_us\":\"%llu\","
	        "\"started_us\":\"%llu\",\"last_applied_us\":\"%llu\",\"lease_until_us\":\"%llu\","
	        "\"iteration\":%u,\"next_event\":%u,\"applied_events\":%u,\"max_lateness_us\":%u,"
	        "\"pad\":{\"buttons\":%u,\"lx\":%u,\"ly\":%u,\"rx\":%u,\"ry\":%u}}}",
	        id, status.state, status.error, (unsigned long long)status.request_id,
	        (unsigned long long)status.now_us, (unsigned long long)status.started_us,
	        (unsigned long long)status.last_applied_us, (unsigned long long)status.lease_until_us,
	        status.iteration, status.next_event, status.applied_events, status.max_lateness_us,
	        status.pad.buttons, status.pad.lx, status.pad.ly, status.pad.rx, status.pad.ry);
}

static int touch_panels_reply(const struct vau_native_api *api, char *out, size_t capacity,
                              const char *id)
{
	char panels[2][512];
	uint64_t begin = api->clock(api->context);

	for (unsigned port = 0; port < 2; port++) {
		struct vau_touch_panel p = { 0 };
		int rc = api->touch_panel ? api->touch_panel(api->context, port, &p) : VAU_UNSUPPORTED;

		if (rc >= 0 && (p.min_active_x >= p.max_active_x || p.min_active_y >= p.max_active_y ||
		                p.min_display_x >= p.max_display_x || p.min_display_y >= p.max_display_y ||
		                p.min_force > p.max_force || p.max_force > 255)) {
			rc = VAU_DEVICE_ERROR;
		}

		if (rc < 0) {
			vau_snprintf(panels[port], sizeof(panels[port]),
			             "{\"port\":%u,\"name\":\"%s\",\"geometry\":null,\"error_code\":%d}", port,
			             port ? "back" : "front", rc);
		} else {
			vau_snprintf(panels[port], sizeof(panels[port]),
			             "{\"port\":%u,\"name\":\"%s\",\"geometry\":{"
			             "\"active\":{\"min_x\":%d,\"min_y\":%d,\"max_x\":%d,\"max_y\":%d},"
			             "\"display\":{\"min_x\":%d,\"min_y\":%d,\"max_x\":%d,\"max_y\":%d},"
			             "\"force\":{\"min\":%u,\"max\":%u}},\"error_code\":0}",
			             port, port ? "back" : "front", p.min_active_x, p.min_active_y,
			             p.max_active_x, p.max_active_y, p.min_display_x, p.min_display_y,
			             p.max_display_x, p.max_display_y, p.min_force, p.max_force);
		}
	}

	return vau_snprintf(
	        out, capacity,
	        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{\"begin_us\":\"%llu\",\"end_us\":\"%llu\",\"coordinate_space\":\"native_touch\",\"panels\":[%s,%s]}}",
	        id, (unsigned long long)begin, (unsigned long long)api->clock(api->context), panels[0],
	        panels[1]);
}

/* One shared parse workspace: too large for the calling thread's stack. The
 * flag turns accidental unserialized re-entry into VAU_BUSY, not corruption. */
static struct {
	struct vau_command command;
	struct vau_json_token tokens[VAU_COMMAND_TOKENS];
} workspace;

static atomic_flag workspace_busy = ATOMIC_FLAG_INIT;

static void command_digest(const struct vau_command *command, unsigned char digest[32])
{
	struct vau_sha256 hash;

	vau_sha256_init(&hash);

	/* The header is zero-initialized on every parse, including padding. Hash
	 * only populated array entries, never unused or stale workspace bytes.
	 * Decoded commands retain equivalent-key-order/Unicode retry behavior. */
	vau_sha256_update(&hash, command, offsetof(struct vau_command, events));
	vau_sha256_update(&hash, command->events, command->sequence.count * sizeof(*command->events));
	vau_sha256_update(&hash, &command->has_touch, sizeof(command->has_touch));
	if (command->has_touch)
		vau_sha256_update(&hash, command->touch, command->sequence.count * sizeof(*command->touch));
	vau_sha256_finish(&hash, digest);
}

static int request_locked(struct vau_session *s, const struct vau_native_api *api,
                          const char *request, size_t length, char *response, size_t capacity)
{
	if (!s || !api || !api->clock || !response || capacity < VAU_RESPONSE_BYTES)
		return VAU_INVALID;

	s->reboot_reply = 0;

	struct vau_command *command = &workspace.command;
	int rc                      = parse(request, length, command, workspace.tokens);

	if (rc < 0)
		return error_reply(response, capacity, "null", rc);

	char id[24];

	vau_snprintf(id, sizeof(id), "\"%llu\"", (unsigned long long)command->id);

	/*
	 * Read-only operations need OBSERVE, everything else CONTROL. Note that
	 * every operation from OP_EVENTS_START on defaults to OBSERVE, so a new
	 * effectful operation appended to the enum must also join the CONTROL
	 * list just below.
	 */
	unsigned right = command->operation <= OP_SNAPSHOT || (command->operation == OP_FILE_STAT ||
	                                                       command->operation == OP_FILE_LIST ||
	                                                       command->operation == OP_TOUCH_PANELS ||
	                                                       command->operation == OP_APP_LIST ||
	                                                       command->operation == OP_PLUGIN_LIST ||
	                                                       (command->operation >= OP_PERF_MEASURE &&
	                                                        command->operation <= OP_PERF_CANCEL) ||
	                                                       command->operation == OP_APP_RUNNING ||
	                                                       command->operation >= OP_EVENTS_START)
	                         ? VAU_RIGHT_OBSERVE
	                         : VAU_RIGHT_CONTROL;

	if ((command->operation >= OP_RUN_BEGIN && command->operation <= OP_RUN_END) ||
	    command->operation == OP_INSTALL || command->operation == OP_MACRO_ENQUEUE ||
	    command->operation == OP_CONTENT_PREVIEW || command->operation == OP_CONTENT_REQUEST) {
		right = VAU_RIGHT_CONTROL;
	}

	if (!(s->rights & right))
		return error_reply(response, capacity, id, VAU_DENIED);

	/* Check before replay too: a cached input/action success must not look like
	 * new input was accepted while the user is deciding. */
	if (api->approval_pending && api->approval_pending(api->context) &&
	    ((command->operation >= OP_LAUNCH && command->operation <= OP_INPUT_RELEASE) ||
	     command->operation == OP_INSTALL || command->operation == OP_INPUT_SUBMIT ||
	     command->operation == OP_MACRO_ENQUEUE || command->operation == OP_REBOOT ||
	     command->operation == OP_MACRO_ACQUIRE)) {
		return error_reply(response, capacity, id, VAU_BUSY);
	}

	if (api->content_busy && api->content_busy(api->context) &&
	    (command->operation == OP_LAUNCH || command->operation == OP_CLOSE ||
	     command->operation == OP_REBOOT || command->operation == OP_SCREEN_OFF ||
	     (command->operation >= OP_FILE_MKDIR && command->operation <= OP_FILE_PURGE))) {
		return error_reply(response, capacity, id, VAU_BUSY);
	}

	unsigned char digest[32];

	if (command->operation == OP_SCREEN_OFF && s->run_id[0])
		return error_reply(response, capacity, id, VAU_BUSY);

	/* Exactly once per session: the same id with the same command replays the
	 * stored reply without executing again; anything else under it is STALE. */
	command_digest(command, digest);
	if (command->id == s->last_id) {
		if (memcmp(digest, s->last_digest, sizeof(digest)))
			return error_reply(response, capacity, id, VAU_STALE);

		s->reboot_reply = s->reboot_pending;
		memcpy(response, s->reply, s->reply_length + 1);
		return (int)s->reply_length;
	}

	if (s->reboot_pending)
		return error_reply(response, capacity, id, VAU_BUSY);
	if (command->id < s->last_id)
		return error_reply(response, capacity, id, VAU_STALE);

	/* Reserve the ID before crossing into a potentially effectful API. Caller
	 * serialization is mandatory. Even an unexpected encoding failure cannot
	 * make a retry execute the action again. */
	s->last_id = command->id;
	memcpy(s->last_digest, digest, sizeof(digest));

	int n = error_reply(s->reply, sizeof(s->reply), id, VAU_DEVICE_ERROR);

	s->reply_length = (size_t)n;
	if (command->operation == OP_INSTALL || command->operation == OP_INSTALL_STATUS) {
		char result[2048];
		int result_bytes = api->app_install ? api->app_install(api->context, s->handle, s->subject,
		                                                       command->mutation_id, command->path,
		                                                       command->operation == OP_INSTALL,
		                                                       result, sizeof(result))
		                                    : VAU_UNSUPPORTED;

		if (result_bytes < 0) {
			n = error_reply(response, capacity, id, result_bytes);
		} else if ((size_t)result_bytes >= sizeof(result)) {
			n = error_reply(response, capacity, id, VAU_DEVICE_ERROR);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}

		if (n < 0 || (size_t)n >= capacity)
			return VAU_DEVICE_ERROR;

		memcpy(s->reply, response, (size_t)n + 1);
		s->reply_length = (size_t)n;
		return n;
	}

	if (command->operation == OP_CAPABILITIES) {
		n = vau_snprintf(
		        response, capacity,
		        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{"
		        "\"operations\":[\"capabilities\",\"system.snapshot\",\"app.launch\",\"app.close\",\"screen.on\",\"screen.off\",\"input.acquire\",\"input.heartbeat\",\"input.cancel\",\"input.release\",\"input.status\",\"input.submit\",\"fs.stat\",\"fs.list\",\"touch.panels\",\"system.reboot\",\"app.list\",\"fs.mkdir\",\"fs.move\",\"fs.trash\",\"fs.purge\",\"acl.request\",\"acl.status\",\"acl.audit\",\"macro.acquire\",\"plugins.list\",\"app.running\",\"performance.measure\",\"performance.watch\",\"performance.read\",\"performance.cancel\",\"events.start\",\"events.read\",\"events.stop\",\"livearea.schema\",\"log.start\",\"log.read\",\"log.stop\",\"content.list\",\"livearea.layout\",\"livearea.blob\",\"dialog.events.start\",\"dialog.events.read\",\"dialog.events.stop\",\"macro.enqueue\",\"content.delete.status\",\"content.delete.changes\",\"content.audit\",\"content.delete.preview\",\"content.scope\",\"content.delete.request\",\"content.albums\",\"app.install\",\"app.install.status\",\"events.subscribe\",\"run.begin\",\"run.update\",\"run.end\",\"run.status\"],"
		        "\"request_bytes_max\":131072,\"response_bytes_max\":4096,"
		        "\"content_delete\":{\"kinds\":[\"application\",\"vita_savedata\"],\"savedata_user_min\":0,\"savedata_user_max\":63,\"requires_preview\":true,\"requires_physical_ok\":true},"
		        "\"id_order\":\"strictly_increasing_decimal_strings\",\"cached_replies\":1,"
		        "\"plugins\":{\"page_entries_max\":2,\"source\":\"native_module_lists\",\"categories\":\"taihen_config_sections\"},"
		        "\"filesystem\":{\"page_entries_max\":8,\"offset_max\":4294967295,\"scan_reads_max\":128,\"continuation_idle_us\":30000000,\"snapshot\":false,\"read_path\":\"/v1/file/read\",\"read_bytes_max\":16384},"
		        "\"audit\":{\"export_path\":\"/v1/audit\",\"page_events_max\":2,\"response_bytes_max\":16384},"
		        "\"upload\":{\"path\":\"/v1/file/upload\",\"metadata_bytes_max\":3072,\"chunk_bytes_max\":%u,\"encoding\":\"be32_json_length_json_raw\"},"
		        "\"input\":{\"events_max\":1024,\"duration_us_max\":3600000000,\"repeats_max\":1000000,"
		        "\"lease_us\":5000000,\"button_mask\":62457,\"start_clock\":\"device_monotonic_us\",\"start_delay_us_min\":10000,\"start_delay_us_max\":1000000,"
		        "\"process_binding\":false,\"routing\":\"native_current_target\","
		        "\"touch_submission\":true,\"readable_events\":true,\"same_timestamp_disjoint_merge\":true,\"front_contacts_max\":6,\"back_contacts_max\":4,\"touch_fields\":[\"enabled\",\"front\",\"back\"],"
		        "\"contact_fields\":[\"id\",\"force\",\"x\",\"y\"],"
		        "\"event_fields\":[\"at_us\",\"buttons\",\"lx\",\"ly\",\"rx\",\"ry\"],"
		        "\"applied_means\":\"native_api_accepted\"},\"macros\":{\"acquire\":\"macro.acquire\",\"binding\":\"title_id\"},\"performance\":{\"measure\":\"performance.measure\",\"watch\":\"performance.watch\",\"read\":\"performance.read\",\"cancel\":\"performance.cancel\",\"window_ms_min\":100,\"window_ms_max\":60000,\"watch_seconds_max\":3600,\"sample_interval_ms\":1000,\"retained_samples\":64,\"core_order\":[\"CPU0\",\"CPU1\",\"CPU2\",\"CPU3\"]}}}",
		        id, VAU_UPLOAD_CHUNK_BYTES);
	} else if (command->operation == OP_SUBSCRIBE) {
		char result[3500];
		int got = api->events ? api->events(api->context, 0, 0, result, sizeof(result))
		                      : VAU_UNSUPPORTED;

		if (got >= 0 && api->dialog_events)
			got = api->dialog_events(api->context, 0, 0, result, sizeof(result));
		if (got < 0) {
			n = error_reply(response, capacity, id, got);
		} else {
			int tty = api->tty ? api->tty(api->context, 0, 0, result, sizeof(result))
			                   : VAU_UNSUPPORTED;

			s->tty_after = s->tty_dropped = 0;
			if (tty < 0)
				vau_snprintf(result, sizeof(result), "{\"error\":%d}", tty);
			s->push_enabled = 1;
			s->dump_after = s->dialog_after = 0;
			n                               = vau_snprintf(
                    response, capacity,
                    "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{\"transport\":\"persistent_tls_push\",\"coredumps\":true,\"tty\":%s}}",
                    id, result);
		}
	} else if (command->operation >= OP_RUN_BEGIN && command->operation <= OP_RUN_STATUS) {
		rc = VAU_OK;
		if (command->operation == OP_RUN_BEGIN) {
			if (s->run_id[0]) {
				rc = VAU_BUSY;
			} else {
				memcpy(s->run_id, command->mutation_id, 33);
				memcpy(s->run_title, command->title, sizeof(s->run_title));
				strcpy(s->run_phase, "preparing");
				s->run_started_us = api->clock(api->context);
			}
		} else if (command->operation != OP_RUN_STATUS) {
			if (strcmp(s->run_id, command->mutation_id)) {
				rc = VAU_STALE;
			} else {
				strcpy(s->run_phase, command->content_category);
				if (command->operation == OP_RUN_END)
					s->run_id[0] = 0;
			}
		}

		n = rc < 0 ? error_reply(response, capacity, id, rc)
		           : vau_snprintf(
		                     response, capacity,
		                     "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{\"active\":%s,\"run_id\":\"%s\",\"title_id\":\"%s\",\"phase\":\"%s\",\"started_us\":\"%llu\"}}",
		                     id, s->run_id[0] ? "true" : "false", s->run_id, s->run_title,
		                     s->run_phase, (unsigned long long)s->run_started_us);
	} else if (command->operation == OP_SNAPSHOT) {
		n = snapshot_reply(api, response, capacity, id);
	} else if (command->operation >= OP_PERF_MEASURE && command->operation <= OP_PERF_CANCEL) {
		if (command->operation == OP_PERF_MEASURE || command->operation == OP_PERF_WATCH)
			s->perf_after = 0;
		if (command->operation == OP_PERF_CANCEL)
			s->perf_push = 0;
		if (!api->performance) {
			n = error_reply(response, capacity, id, VAU_UNSUPPORTED);
		} else {
			int prefix   = vau_snprintf(response, capacity,
			                            "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":", id);
			int observed = prefix < 0 || (size_t)prefix + 2 >= capacity
			                       ? VAU_DEVICE_ERROR
			                       : api->performance(
			                                 api->context, s->handle,
			                                 command->operation - OP_PERF_MEASURE, command->offset,
			                                 command->operation == OP_PERF_READ ? command->offset
			                                 : command->operation == OP_PERF_WATCH
			                                         ? command->start_delay_us
			                                         : 0,
			                                 response + prefix, capacity - (size_t)prefix - 1);

			if (observed < 0) {
				n = error_reply(response, capacity, id, observed);
			} else {
				if (command->operation == OP_PERF_MEASURE || command->operation == OP_PERF_WATCH)
					s->perf_push = 1;
				n             = prefix + observed;
				response[n++] = '}';
				response[n]   = 0;
			}
		}
	} else if (command->operation >= OP_LOG_START && command->operation <= OP_LOG_STOP) {
		char result[3500];
		int got = api->log_watch ? api->log_watch(api->context, s->subject,
		                                          command->operation - OP_LOG_START, command->path,
		                                          command->log_marker, command->offset, result,
		                                          sizeof(result))
		                         : VAU_UNSUPPORTED;

		if (got < 0) {
			n = error_reply(response, capacity, id, got);
		} else {
			if (command->operation == OP_LOG_START) {
				struct vau_json_token tokens[32];
				size_t count;
				uint64_t watch_id;

				if (!vau_json_parse(result, (size_t)got, tokens, 32, &count) && count > 2 &&
				    !vau_json_u64(result, &tokens[2], &watch_id)) {
					for (unsigned i = 0; i < 4; i++) {
						if (!s->log_ids[i]) {
							s->log_ids[i] = (uint32_t)watch_id;
							break;
						}
					}
				}
			} else if (command->operation == OP_LOG_STOP) {
				for (unsigned i = 0; i < 4; i++)
					if (s->log_ids[i] == command->offset)
						s->log_ids[i] = 0;
			}

			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation == OP_LIVEAREA_BLOB) {
		char result[3500];
		int got = api->livearea_blob
		                  ? api->livearea_blob(api->context, command->content_category,
		                                       command->blob_page, command->blob_position,
		                                       command->blob_column, command->offset, result,
		                                       sizeof(result))
		                  : VAU_UNSUPPORTED;

		if (got < 0) {
			n = metadata_error_reply(api, response, capacity, id, got);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation == OP_LIVEAREA_LAYOUT) {
		char result[3500];
		int got = api->livearea_layout
		                  ? api->livearea_layout(api->context, command->content_category,
		                                         command->offset, result, sizeof(result))
		                  : VAU_UNSUPPORTED;

		if (got < 0) {
			n = metadata_error_reply(api, response, capacity, id, got);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation >= OP_CONTENT_STATUS && command->operation <= OP_CONTENT_ALBUMS) {
		struct vau_content_query q = { .operation = command->operation - OP_CONTENT_STATUS,
			                           .yes       = command->yes,
			                           .kind      = command->content_kind,
			                           .user      = command->content_user,
			                           .before    = command->content_before,
			                           .after     = command->content_after,
			                           .cursor    = command->content_cursor,
			                           .media_id  = command->content_media_id };
		memcpy(q.id, command->mutation_id, sizeof(q.id));
		memcpy(q.title, command->title, sizeof(q.title));

		char result[3072];
		int got = !s->subject[0]       ? VAU_DENIED
		          : api->content_query ? api->content_query(api->context, s->handle, s->subject, &q,
		                                                    result, sizeof(result))
		                               : VAU_UNSUPPORTED;

		if (got < 0) {
			n = error_reply(response, capacity, id, got);
		} else if (got <= 0 || got >= (int)sizeof(result)) {
			n = error_reply(response, capacity, id, VAU_DEVICE_ERROR);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation == OP_CONTENT_LIST) {
		char result[3500];
		int got = api->content_inventory
		                  ? api->content_inventory(api->context, command->content_category,
		                                           command->app_after, result, sizeof(result))
		                  : VAU_UNSUPPORTED;

		if (got < 0) {
			n = metadata_error_reply(api, response, capacity, id, got);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation == OP_LIVEAREA_SCHEMA) {
		char result[3500];
		int got = api->livearea_schema ? api->livearea_schema(api->context, command->app_after,
		                                                      result, sizeof(result))
		                               : VAU_UNSUPPORTED;

		if (got < 0) {
			n = error_reply(response, capacity, id, got);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation >= OP_DIALOG_START && command->operation <= OP_DIALOG_STOP) {
		char result[3500];
		int got = api->dialog_events
		                  ? api->dialog_events(api->context, command->operation - OP_DIALOG_START,
		                                       command->offset, result, sizeof(result))
		                  : VAU_UNSUPPORTED;

		if (got < 0) {
			n = error_reply(response, capacity, id, got);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation >= OP_EVENTS_START && command->operation <= OP_EVENTS_STOP) {
		char result[3500];
		int got = api->events ? api->events(api->context, command->operation - OP_EVENTS_START,
		                                    command->offset, result, sizeof(result))
		                      : VAU_UNSUPPORTED;

		if (got < 0) {
			n = error_reply(response, capacity, id, got);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation == OP_APP_RUNNING) {
		char result[3000];
		int got = api->app_running ? api->app_running(api->context, result, sizeof(result))
		                           : VAU_UNSUPPORTED;

		if (got < 0) {
			n = error_reply(response, capacity, id, got);
		} else {
			n = vau_snprintf(response, capacity,
			                 "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":%s}", id, result);
		}
	} else if (command->operation == OP_PLUGIN_LIST) {
		if (!api->plugin_list) {
			n = error_reply(response, capacity, id, VAU_UNSUPPORTED);
		} else {
			int prefix = vau_snprintf(response, capacity,
			                          "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":", id);
			int rc     = prefix < 0 || (size_t)prefix + 2 >= capacity
			                     ? VAU_DEVICE_ERROR
			                     : api->plugin_list(api->context, command->offset, response + prefix,
			                                        capacity - (size_t)prefix - 1);

			if (rc < 0) {
				n = error_reply(response, capacity, id, rc);
			} else {
				n             = prefix + rc;
				response[n++] = '}';
				response[n]   = 0;
			}
		}
	} else if (command->operation == OP_TOUCH_PANELS) {
		n = touch_panels_reply(api, response, capacity, id);
	} else if (command->operation == OP_MACRO_ENQUEUE) {
		uint64_t execution = 0;

		rc = api->input_enqueue
		             ? api->input_enqueue(api->input_context, s->handle, &command->sequence,
		                                  command->events,
		                                  command->has_touch ? command->touch : NULL, &execution)
		             : VAU_UNSUPPORTED;
		if (rc < 0) {
			n = error_reply(response, capacity, id, rc);
		} else {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"accepted\",\"execution_id\":\"%llu\",\"start_source\":\"prior_segment_end\"}",
			        id, (unsigned long long)execution);
		}
	} else if (command->operation == OP_INPUT_SUBMIT) {
		uint64_t execution    = 0;
		VauSequence scheduled = command->sequence;

		if (command->start_delay_us) {
			uint64_t now    = api->clock(api->context),
			         length = (uint64_t)scheduled.duration_us * scheduled.repeats;

			if (now > UINT64_MAX - command->start_delay_us ||
			    now + command->start_delay_us > UINT64_MAX - length) {
				rc = VAU_INVALID;
			} else {
				scheduled.start_us = now + command->start_delay_us;
				rc                 = VAU_OK;
			}
		} else {
			rc = VAU_OK;
		}

		if (rc < 0) { /* No submit on clock overflow. */
		} else if (command->has_touch) {
			rc = api->input_submit_touch
			             ? api->input_submit_touch(api->input_context, s->handle, &scheduled,
			                                       command->events, command->touch, &execution)
			             : VAU_UNSUPPORTED;
		} else {
			rc = api->input_submit ? api->input_submit(api->input_context, s->handle, &scheduled,
			                                           command->events, &execution)
			                       : VAU_UNSUPPORTED;
		}

		if (rc < 0) {
			n = error_reply(response, capacity, id, rc);
		} else {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"accepted\",\"execution_id\":\"%llu\",\"start_us\":\"%llu\"}",
			        id, (unsigned long long)execution, (unsigned long long)scheduled.start_us);
		}
	} else if (command->operation == OP_ACL_AUDIT) {
		char data[1025], quoted[3075];

		rc = api->acl_audit ? api->acl_audit(api->context, command->offset, data, sizeof(data))
		                    : VAU_UNSUPPORTED;
		if (rc < 0) {
			n = error_reply(response, capacity, id, rc);
		} else if (rc > 1024 || vau_json_quote(data, quoted, sizeof(quoted)) < 0) {
			n = error_reply(response, capacity, id, VAU_DEVICE_ERROR);
		} else {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{\"offset\":%u,\"next_offset\":%u,\"data\":%s}}",
			        id, command->offset, command->offset + (unsigned)rc, quoted);
		}
	} else if (command->operation == OP_ACL_REQUEST || command->operation == OP_ACL_STATUS) {
		int state = 0, native_result = 0;

		rc                               = !s->subject[0] ? VAU_DENIED
		                                   : api->acl ? api->acl(api->context, s->handle, s->subject, command->mutation_id,
		                                                         command->path, command->operation == OP_ACL_REQUEST, &state,
		                                                         &native_result)
		                                              : VAU_UNSUPPORTED;
		static const char *const names[] = { "unknown", "pending", "approved", "denied", "failed" };
		if (rc < 0 || state < 1 || state > 4) {
			n = error_reply(response, capacity, id, rc < 0 ? rc : VAU_DEVICE_ERROR);
		} else {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{\"request_id\":\"%s\",\"state\":\"%s\",\"allow\":2,\"persistent\":true,\"native_result\":%d}}",
			        id, command->mutation_id, names[state], native_result);
		}
	} else if (command->operation >= OP_FILE_MKDIR && command->operation <= OP_FILE_PURGE) {
		struct vau_write_request mutation = { 0 };
		struct vau_write_record record    = { 0 };

		strcpy(mutation.id, command->mutation_id);
		strcpy(mutation.subject, s->subject);
		strcpy(mutation.path, command->path);
		strcpy(mutation.destination, command->destination);
		mutation.yes = command->yes;
		strcpy(mutation.trash_id, command->trash_id);
		mutation.operation = command->operation == OP_FILE_MKDIR   ? VAU_FS_MKDIR
		                     : command->operation == OP_FILE_MOVE  ? VAU_FS_RENAME_SOURCE
		                     : command->operation == OP_FILE_PURGE ? VAU_FS_PURGE
		                                                           : VAU_FS_TRASH;
		rc                 = !s->subject[0]     ? VAU_DENIED
		                     : api->file_mutate ? api->file_mutate(api->context, &mutation, &record)
		                                        : VAU_UNSUPPORTED;

		char path_json[VAU_PATH_MAX * 6 + 3];

		if (vau_json_quote(mutation.path, path_json, sizeof(path_json)) < 0)
			return VAU_DEVICE_ERROR;

		char changes[VAU_RESPONSE_BYTES];
		int changed = vau_write_changes_json(&record, changes, sizeof(changes));

		if (changed < 0 || changed >= (int)sizeof(changes))
			return VAU_DEVICE_ERROR;

		n = vau_snprintf(
		        response, capacity,
		        "{\"v\":1,\"id\":%s,\"status\":\"%s\",\"result\":{"
		        "\"operation_id\":\"%s\",\"path\":%s,\"trash_id\":\"%s\",\"code\":%d,\"sequence\":\"%llu\",\"effect_started\":%s,\"readback_required\":%s,\"changes\":%s}}",
		        id, rc ? "error" : "ok", mutation.id, path_json, mutation.trash_id, rc,
		        (unsigned long long)record.sequence, record.effect_started ? "true" : "false",
		        record.readback_required ? "true" : "false", changes);
	} else if (command->operation == OP_FILE_LIST) {
		struct vau_file_page page;

		rc = vau_file_list(api->file_list, api->context, command->path, command->offset, &page);
		if (rc < 0) {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"error\",\"error\":{\"source\":\"filesystem\",\"code\":%d}}",
			        id, rc);
		} else {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{\"observed_us\":\"%llu\",\"next_offset\":%u,\"more\":%s,\"entries\":[",
			        id, (unsigned long long)api->clock(api->context), page.next_offset,
			        page.more ? "true" : "false");
			for (uint32_t i = 0; i < page.count && n > 0 && (size_t)n < capacity; i++) {
				char quoted[1533];

				if (vau_json_quote(page.entries[i].name, quoted, sizeof(quoted)) < 0) {
					n = -1;
					break;
				}

				struct vau_file_info *info = &page.entries[i].info;
				char modified[64];

				if (!info->year || !info->month || !info->day) {
					memcpy(modified, "null", 5);
				} else {
					vau_snprintf(modified, sizeof(modified),
					             "\"%04u-%02u-%02uT%02u:%02u:%02u.%06u\"", info->year, info->month,
					             info->day, info->hour, info->minute, info->second,
					             info->microsecond);
				}

				int added = vau_snprintf(
				        response + n, capacity - (size_t)n,
				        "%s{\"name\":%s,\"kind\":\"%s\",\"bytes\":\"%llu\",\"mode\":%u,\"attributes\":%u,\"modified\":%s}",
				        i ? "," : "", quoted,
				        info->kind == VAU_FILE_REGULAR     ? "file"
				        : info->kind == VAU_FILE_DIRECTORY ? "directory"
				                                           : "other",
				        (unsigned long long)info->bytes, info->mode, info->attributes, modified);

				if (added < 0) {
					n = -1;
					break;
				}

				n += added;
			}

			if (n > 0 && (size_t)n < capacity)
				n += vau_snprintf(response + n, capacity - (size_t)n, "]}}");
		}
	} else if (command->operation == OP_APP_LIST) {
		struct vau_app_page page = { 0 };

		rc = api->app_list
		             ? api->app_list(api->context, command->app_after, command->app_query, &page)
		             : VAU_UNSUPPORTED;
		if (rc || page.count > VAU_APP_PAGE_ENTRIES) {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"error\",\"error\":{\"source\":\"app_registry\",\"code\":%d}}",
			        id, rc ? rc : VAU_DEVICE_ERROR);
		} else {
			char cursor[195];

			if (vau_json_quote(page.next_after, cursor, sizeof(cursor)) < 0)
				return VAU_DEVICE_ERROR;

			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{"
			        "\"source\":\"livearea_app_registry\",\"snapshot\":false,\"next_after\":%s,\"more\":%s,\"entries\":[",
			        id, cursor, page.more ? "true" : "false");
			for (uint32_t i = 0; i < page.count && n > 0 && (size_t)n < capacity; i++) {
				char title[195], name[VAU_APP_NAME_BYTES * 6 + 3], category[99];
				struct vau_app_entry *entry = &page.entries[i];

				if (vau_json_quote(entry->title_id, title, sizeof(title)) < 0 ||
				    vau_json_quote(entry->name, name, sizeof(name)) < 0 ||
				    vau_json_quote(entry->category, category, sizeof(category)) < 0) {
					n = -1;
					break;
				}

				int added = vau_snprintf(
				        response + n, capacity - (size_t)n,
				        "%s{\"title_id\":%s,\"name\":%s,\"category\":%s,\"launchable\":%s}",
				        i ? "," : "", title, name, category,
				        vau_title_valid(entry->title_id) ? "true" : "false");

				if (added < 0) {
					n = -1;
					break;
				}

				n += added;
			}

			if (n > 0 && (size_t)n < capacity)
				n += vau_snprintf(response + n, capacity - (size_t)n, "]}}");
		}
	} else if (command->operation == OP_FILE_STAT) {
		struct vau_file_info info;

		rc = vau_file_stat(api->file_stat, api->context, command->path, &info);
		if (rc < 0) {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"error\",\"error\":{\"source\":\"filesystem\",\"code\":%d}}",
			        id, rc);
		} else {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"ok\",\"result\":{\"observed_us\":\"%llu\","
			        "\"kind\":\"%s\",\"bytes\":\"%llu\",\"mode\":%u,\"attributes\":%u,"
			        "\"modified\":{\"year\":%u,\"month\":%u,\"day\":%u,\"hour\":%u,\"minute\":%u,\"second\":%u,\"microsecond\":%u}}}",
			        id, (unsigned long long)api->clock(api->context),
			        info.kind == VAU_FILE_REGULAR     ? "file"
			        : info.kind == VAU_FILE_DIRECTORY ? "directory"
			                                          : "other",
			        (unsigned long long)info.bytes, info.mode, info.attributes, info.year,
			        info.month, info.day, info.hour, info.minute, info.second, info.microsecond);
		}
	} else if (command->operation == OP_REBOOT) {
		if (!api->reboot) {
			n = error_reply(response, capacity, id, VAU_UNSUPPORTED);
		} else {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"accepted\",\"result\":{\"reboot\":\"after_response\"}}",
			        id);
			s->reboot_pending = s->reboot_reply = 1;
		}
	} else if (command->operation == OP_MACRO_ACQUIRE) {
		struct vau_foreground foreground;

		rc = vau_native_foreground(api, &foreground);
		if (rc >= 0 &&
		    (foreground.kind != VAU_FOREGROUND_APP || strcmp(foreground.title, command->title))) {
			rc = VAU_STALE;
		}

		if (rc < 0)
			n = error_reply(response, capacity, id, rc);
		else
			n = input_reply(s, api, OP_INPUT_ACQUIRE, foreground.pid, response, capacity, id);
	} else if (command->operation >= OP_INPUT_ACQUIRE) {
		n = input_reply(s, api, command->operation, command->process, response, capacity, id);
	} else {
		struct vau_native_reply result;
		enum vau_native_operation op = command->operation == OP_LAUNCH      ? VAU_APP_LAUNCH
		                               : command->operation == OP_CLOSE     ? VAU_APP_CLOSE
		                               : command->operation == OP_SCREEN_ON ? VAU_SCREEN_ON
		                                                                    : VAU_SCREEN_OFF;

		vau_native_execute(api, op, command->title[0] ? command->title : NULL, &result);
		if (result.state == VAU_NATIVE_ACCEPTED) {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"accepted\",\"observed_us\":\"%llu\",\"native_result\":%d}",
			        id, (unsigned long long)result.observed_us, result.native_result);
		} else {
			n = vau_snprintf(
			        response, capacity,
			        "{\"v\":1,\"id\":%s,\"status\":\"error\",\"observed_us\":\"%llu\",\"error\":{\"source\":\"native\",\"code\":%d}}",
			        id, (unsigned long long)result.observed_us, result.native_result);
		}
	}

	if (n < 0 || (size_t)n >= VAU_RESPONSE_BYTES) {
		memcpy(response, s->reply, s->reply_length + 1);
		return (int)s->reply_length;
	}

	memcpy(s->reply, response, (size_t)n + 1);
	s->reply_length = (size_t)n;
	return n;
}

/* Only the fully validated event subscription is background maintenance.
 * Reuse the existing bounded parser workspace; no client-supplied bypass flag. */
int vau_protocol_background_request(const char *request, size_t length)
{
	if (!request || atomic_flag_test_and_set_explicit(&workspace_busy, memory_order_acquire))
		return 0;

	int rc         = parse(request, length, &workspace.command, workspace.tokens);
	int background = rc == VAU_OK && workspace.command.operation == OP_SUBSCRIBE;

	atomic_flag_clear_explicit(&workspace_busy, memory_order_release);
	return background;
}

int vau_protocol_request(struct vau_session *s, const struct vau_native_api *api,
                         const char *request, size_t length, char *response, size_t capacity)
{
	if (!s || !api || !response || capacity < VAU_RESPONSE_BYTES)
		return VAU_INVALID;
	if (atomic_flag_test_and_set_explicit(&workspace_busy, memory_order_acquire))
		return error_reply(response, capacity, "null", VAU_BUSY);

	int rc = request_locked(s, api, request, length, response, capacity);

	atomic_flag_clear_explicit(&workspace_busy, memory_order_release);
	return rc;
}
