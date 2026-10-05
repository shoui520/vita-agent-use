/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "native_ops.h"
#include "vau_modules.h"
#include "tai_config_guard.h"
#include "json.h"
#include "format.h"
#include <psp2/appmgr.h>
#include <psp2/kernel/processmgr.h>
#include <string.h>

extern void *vauPafMalloc(size_t);
extern void vauPafFree(void *);

struct process {
	int pid;
	char title[VAU_TITLE_BYTES];
};

static int observe(const char *section, const char path[256], const struct process *processes,
                   unsigned count, VauPluginState *state, unsigned *instances)
{
	memset(state, 0, sizeof(*state));
	*instances = 0;
	if (!strcmp(section, "*KERNEL")) {
		/* 0x10005 is the kernel process (taiHEN's KERNEL_PID), home of *KERNEL plugins. */
		int rc = vauPluginState(0x10005, path, state);

		if (rc >= 0)
			*instances = state->loaded;
		return rc;
	}

	if (strcmp(section, "*ALL") && strcmp(section, "*main") &&
	    (section[0] != '*' || !vau_title_valid(section + 1))) {
		return VAU_UNSUPPORTED;
	}

	for (unsigned i = 0; i < count; i++) {
		if (strcmp(section, "*ALL") && strcmp(section + 1, processes[i].title))
			continue;

		VauPluginState observed = { 0 };
		int rc                  = vauPluginState(processes[i].pid, path, &observed);

		if (rc < 0)
			return rc;
		if (observed.loaded) {
			*state = observed;
			++*instances;
		}
	}

	return VAU_OK;
}

int vau_vita_plugin_list(void *context, uint32_t offset, char *out, size_t cap)
{
	(void)context;

	const char *config = "ux0:tai/config.txt";
	struct vau_file_info stat;
	int rc = vau_vita_file_stat(NULL, config, &stat);

	if (rc == (int)0x80010002u) {
		config = "ur0:tai/config.txt";
		rc     = vau_vita_file_stat(NULL, config, &stat);
	}

	if (rc < 0)
		return rc;

	char *text = vauPafMalloc(VAU_TAI_CONFIG_BYTES + 1);

	if (!text)
		return VAU_DEVICE_ERROR;

	struct vau_file_chunk chunk;

	rc = vau_vita_file_read(NULL, config, 0, text, VAU_TAI_CONFIG_BYTES, &chunk);
	if (rc < 0 || chunk.file_bytes > VAU_TAI_CONFIG_BYTES || chunk.count != chunk.file_bytes) {
		vauPafFree(text);
		return rc < 0 ? rc : VAU_UNSUPPORTED;
	}

	if (memchr(text, 0, chunk.count)) {
		vauPafFree(text);
		return VAU_DEVICE_ERROR;
	}

	text[chunk.count] = 0;

	int apps[20];
	struct process processes[21] = { 0 };
	unsigned process_count       = 1;

	processes[0].pid = sceKernelGetProcessId();
	strcpy(processes[0].title, "main");

	int app_count     = sceAppMgrGetRunningAppIdListForShell(apps, 20);
	int process_error = app_count < 0 ? app_count : app_count >= 20 ? VAU_UNSUPPORTED : 0;

	for (int i = 0; i < app_count && !process_error; i++) {
		int pid = sceAppMgrGetProcessIdByAppIdForShell(apps[i]);

		if (pid == processes[0].pid)
			continue;
		if (pid < 0) {
			process_error = pid;
			break;
		}

		char title[SCE_APPMGR_MAX_APP_NAME_LENGTH + 1] = { 0 };

		rc = sceAppMgrGetNameById(pid, title);
		if (rc < 0) {
			process_error = rc;
			break;
		}

		if (!vau_title_valid(title)) {
			process_error = VAU_DEVICE_ERROR;
			break;
		}

		processes[process_count].pid = pid;
		memcpy(processes[process_count++].title, title, VAU_TITLE_BYTES);
	}

	char section[16] = "";
	uint32_t index = 0, next = offset, count = 0;
	int more = 0;
	int n    = vau_snprintf(
            out, cap,
            "{\"config_path\":\"%s\",\"source\":\"native_module_lists\",\"snapshot\":false,\"entries\":[",
            config);
	if (n < 0 || (size_t)n >= cap) {
		vauPafFree(text);

		return VAU_DEVICE_ERROR;
	}

	for (char *line = text; line < text + chunk.count;) {
		char *end = memchr(line, '\n', (size_t)(text + chunk.count - line));

		if (!end)
			end = text + chunk.count;

		char *following = end == text + chunk.count ? end : end + 1;

		*end = 0;
		while (*line == ' ' || *line == '\t' || *line == '\r')
			line++;

		size_t length = strlen(line);

		while (length &&
		       (line[length - 1] == '\r' || line[length - 1] == ' ' || line[length - 1] == '\t')) {
			line[--length] = 0;
		}

		if (*line == '*') {
			if (length >= sizeof(section)) {
				rc = VAU_DEVICE_ERROR;
				break;
			}

			memcpy(section, line, length + 1);
		} else if (section[0]) {
			int configured = 1;

			if (*line == '#') {
				configured = 0;
				line++;
				while (*line == ' ' || *line == '\t')
					line++;
			}

			char path[256] = { 0 };

			if (strchr(line, ':') && !vau_path_normalize(line, path, sizeof(path))) {
				if (index++ >= offset) {
					if (count >= 2) {
						more = 1;
						break;
					}

					VauPluginState state = { 0 };
					unsigned instances   = 0;
					int observed =
					        strcmp(section, "*KERNEL") && strcmp(section, "*main") && process_error
					                ? process_error
					                : observe(section, path, processes, process_count, &state,
					                          &instances);
					char quoted_path[1539], quoted_section[99], quoted_module[171],
					        native_state[24];

					vau_snprintf(native_state, sizeof(native_state), "%u", state.native_state);
					if (vau_json_quote(path, quoted_path, sizeof(quoted_path)) < 0 ||
					    vau_json_quote(section, quoted_section, sizeof(quoted_section)) < 0 ||
					    vau_json_quote(state.module_name, quoted_module, sizeof(quoted_module)) <
					            0) {
						rc = VAU_DEVICE_ERROR;
						break;
					}

					int added = vau_snprintf(
					        out + n, cap - (size_t)n,
					        "%s{\"section\":%s,\"path\":%s,\"configured_enabled\":%s,\"loaded\":%s,\"loaded_processes\":%u,\"module_name\":%s,\"native_state\":%s,\"error_code\":%d}",
					        count ? "," : "", quoted_section, quoted_path,
					        configured ? "true" : "false",
					        observed < 0 ? "null"
					        : instances  ? "true"
					                     : "false",
					        instances, observed < 0 || !instances ? "null" : quoted_module,
					        observed < 0 || !instances ? "null" : native_state,
					        observed < 0 ? observed : 0);

					if (added < 0 || (size_t)added + 100 >= cap - (size_t)n) {
						rc = VAU_DEVICE_ERROR;
						break;
					}

					n += added;
					count++;
					next = index;
				}
			}
		}

		line = following;
	}

	vauPafFree(text);
	if (rc < 0)
		return rc;

	int added = vau_snprintf(out + n, cap - (size_t)n,
	                         "],\"next_offset\":%u,\"more\":%s,\"process_error_code\":%d}", next,
	                         more ? "true" : "false", process_error);

	return added < 0 || (size_t)added >= cap - (size_t)n ? VAU_DEVICE_ERROR : n + added;
}

/* Same native AppMgr registry used for loaded application plugin observations.
 * Never infer running state from an installed app directory. */
int vau_vita_app_running(void *context, char *out, size_t cap)
{
	(void)context;

	int apps[20];
	int count = sceAppMgrGetRunningAppIdListForShell(apps, 20);

	if (count < 0)
		return count;
	if (count >= 20)
		return VAU_UNSUPPORTED; /* Native list has no truncation cursor. */

	int n = vau_snprintf(out, cap,
	                     "{\"source\":\"native_appmgr\",\"snapshot\":false,\"entries\":[");

	if (n < 0 || (size_t)n >= cap)
		return VAU_DEVICE_ERROR;

	for (int i = 0; i < count; i++) {
		int pid = sceAppMgrGetProcessIdByAppIdForShell(apps[i]);

		if (pid < 0)
			return pid;

		char title[SCE_APPMGR_MAX_APP_NAME_LENGTH + 1] = { 0 };
		int rc                                         = sceAppMgrGetNameById(pid, title);

		if (rc < 0)
			return rc;
		if (!vau_title_valid(title))
			return VAU_DEVICE_ERROR;

		int added = vau_snprintf(out + n, cap - (size_t)n,
		                         "%s{\"app_id\":%d,\"pid\":%d,\"title_id\":\"%s\"}", i ? "," : "",
		                         apps[i], pid, title);

		if (added < 0 || (size_t)added >= cap - (size_t)n)
			return VAU_DEVICE_ERROR;

		n += added;
	}

	int added = vau_snprintf(out + n, cap - (size_t)n, "],\"entry_count\":%d,\"complete\":true}",
	                         count);

	return added < 0 || (size_t)added >= cap - (size_t)n ? VAU_DEVICE_ERROR : n + added;
}
