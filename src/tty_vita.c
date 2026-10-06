/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "native_ops.h"
#include "vau_tty.h"
#include "format.h"

int vau_vita_tty(void *context, uint32_t operation, uint32_t after, char *out, size_t cap)
{
	(void)context;

	VauTtyPage page = { 0 };
	int rc          = vauTtyRead(operation, after, &page);

	if (rc < 0)
		return rc;
	if (page.size != sizeof(page) || page.abi != VAU_ABI || page.count > VAU_TTY_PAGE_RECORDS)
		return VAU_DEVICE_ERROR;

	int n = vau_snprintf(out, cap,
	                     "{\"next\":%u,\"latest\":%u,\"more\":%s,\"lost\":%u,\"dropped\":%u,"
	                     "\"kernel_error\":%d,\"user_error\":%d,\"events\":[",
	                     page.next, page.latest, page.more ? "true" : "false", page.lost,
	                     page.dropped, page.kernel_error, page.user_error);

	if (n < 0 || (size_t)n >= cap)
		return VAU_DEVICE_ERROR;

	for (unsigned i = 0; i < page.count; i++) {
		VauTtyRecord *record = &page.records[i];
		char hex[VAU_TTY_BYTES * 2 + 1];
		static const char digits[] = "0123456789abcdef";

		if (record->length > VAU_TTY_BYTES ||
		    (record->source != VAU_TTY_KERNEL && record->source != VAU_TTY_USER))
			return VAU_DEVICE_ERROR;

		/* Native printf is a byte stream: retain NULs and non-UTF-8 bytes exactly. */
		for (unsigned j = 0; j < record->length; j++) {
			hex[j * 2]     = digits[record->data[j] >> 4];
			hex[j * 2 + 1] = digits[record->data[j] & 15];
		}
		hex[record->length * 2] = 0;

		int added = vau_snprintf(
		        out + n, cap - (size_t)n,
		        "%s{\"type\":\"tty.data\",\"sequence\":%u,\"source\":\"%s\",\"pid\":%d,"
		        "\"observed_us\":\"%llu\",\"encoding\":\"hex\",\"data\":\"%s\"}",
		        i ? "," : "", record->sequence,
		        record->source == VAU_TTY_KERNEL ? "kernel" : "user", record->pid,
		        (unsigned long long)record->observed_us, hex);

		if (added < 0 || (size_t)added >= cap - (size_t)n)
			return VAU_DEVICE_ERROR;
		n += added;
	}

	int added = vau_snprintf(out + n, cap - (size_t)n, "]}");

	return added < 0 || (size_t)added >= cap - (size_t)n ? VAU_DEVICE_ERROR : n + added;
}
