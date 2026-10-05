/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "native_ops.h"
#include "format.h"
#include <psp2/kernel/threadmgr.h>
#include <taihen.h>
#include <stdatomic.h>
#include <string.h>

/* SceCommonGuiDialog's 3.65 error-text builder calls this verified import
 * with a 16-byte output string and the raw error at record+0x44. No offsets
 * are used for hooking. This is formatting evidence, not display completion. */
struct error_event {
	uint64_t observed_us;
	uint32_t sequence, code;
};
static struct error_event events[16];
static uint32_t latest, count;
static atomic_flag busy = ATOMIC_FLAG_INIT;
static _Atomic uint32_t enabled, dropped;
static tai_hook_ref_t error_ref;
static int hook_id = -1;

static int error_string(char *out, int code)
{
	int rc = TAI_CONTINUE(int, error_ref, out, code);

	if (rc < 0 || !atomic_load_explicit(&enabled, memory_order_relaxed))
		return rc;
	if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire)) {
		atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
		return rc;
	}

	if (latest == UINT32_MAX) {
		atomic_fetch_add_explicit(&dropped, 1, memory_order_relaxed);
	} else {
		uint32_t sequence = ++latest;

		events[(sequence - 1) % 16] =
		        (struct error_event){ sceKernelGetSystemTimeWide(), sequence, (uint32_t)code };
		if (count < 16)
			count++;
	}

	atomic_flag_clear_explicit(&busy, memory_order_release);
	return rc;
}

int vau_vita_dialog_events(void *ctx, uint32_t operation, uint32_t after, char *out, size_t cap)
{
	(void)ctx;
	if (operation > 2 || !out || cap < 3500)
		return VAU_INVALID;
	if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire))
		return VAU_BUSY;

	int rc = VAU_OK;

	if (operation == 0) {
		/* Lazy registration: module start never hooks or waits on the GUI.
		 * Shell plugin cannot unload (STOP_CANCEL), so the passive hook's code
		 * stays resident after stop. Shared GUI modules remain Shell-owned. */
		if (hook_id < 0) {
			hook_id = taiHookFunctionImport(&error_ref, "SceCommonGuiDialog", 0xD401318D,
			                                0xA4DE5B69, error_string);
		}

		if (hook_id < 0) {
			rc = hook_id;
			goto done;
		}

		atomic_store(&enabled, 1);
		after = latest;
	} else if (operation == 2) {
		atomic_store(&enabled, 0);
		after = latest;
	}

	if (after > latest) {
		rc = VAU_STALE;
		goto done;
	}

	uint32_t first = latest - count, lost = after < first ? first - after : 0;

	if (after < first)
		after = first;

	struct error_event page[4];
	unsigned used = 0;

	while (after < latest && used < 4)
		page[used++] = events[after++ % 16];

	int n = vau_snprintf(
	        out, cap,
	        "{\"source\":\"native_common_gui_error_formatter\",\"enabled\":%s,\"next\":%u,\"latest\":%u,\"more\":%s,\"lost\":%u,\"dropped\":%u,\"events\":[",
	        atomic_load(&enabled) ? "true" : "false", after, latest,
	        after < latest ? "true" : "false", lost, atomic_load(&dropped));

	if (n < 0 || (size_t)n >= cap) {
		rc = VAU_DEVICE_ERROR;
		goto done;
	}

	for (unsigned i = 0; i < used; i++) {
		struct error_event *e = &page[i];
		int add               = vau_snprintf(
                out + n, cap - (size_t)n,
                "%s{\"sequence\":%u,\"type\":\"dialog.error\",\"observed_us\":\"%llu\",\"code\":%d,\"raw_hex\":\"0x%08x\",\"display_confirmed\":false}",
                i ? "," : "", e->sequence, (unsigned long long)e->observed_us, (int32_t)e->code,
                e->code);

		if (add < 0 || (size_t)add >= cap - (size_t)n) {
			rc = VAU_DEVICE_ERROR;
			goto done;
		}

		n += add;
	}

	int add = vau_snprintf(out + n, cap - (size_t)n, "]}");

	rc = add < 0 || (size_t)add >= cap - (size_t)n ? VAU_DEVICE_ERROR : n + add;
done:
	atomic_flag_clear_explicit(&busy, memory_order_release);
	return rc;
}
