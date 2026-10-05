/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "config_native.h"
#include "tai_config_guard.h"
#include "file_ops.h"
#include <mbedtls/sha256.h>
#include <string.h>

extern void *vauPafMalloc(size_t);
extern void vauPafFree(void *);

/* Audited VitaShell 2.02 distribution. Matching metadata alone is not an
 * executable validation. Never accept an agent-supplied executable digest.
 * More audited recovery builds may be added explicitly. */
static const struct recovery_file {
	const char *path;
	uint64_t bytes;
	const char *sha256;
} recovery_files[] = { { "uma0:app/VITASHELL/sce_sys/param.sfo", 912,
	                     "ed67d53ca0ef6525e051a0970c8877140aec2f5003a36b7d02a8ddf2104bfe80" },
	                   { "uma0:app/VITASHELL/eboot.bin", 1838437,
	                     "ece0d4e7d5675130d4e1bbb1f962043bb57a72acff78a8b9b0b0485673811d71" } };

int vau_config_recovery_copy_check(struct vau_upload_context *c)
{
	if (!c || !c->stopped)
		return VAU_INVALID;

	for (unsigned i = 0; i < sizeof(recovery_files) / sizeof(*recovery_files); ++i) {
		if (c->stopped(c->context))
			return VAU_DENIED;

		struct vau_file_info info;
		int rc = vau_vita_file_stat(NULL, recovery_files[i].path, &info);

		if (rc || info.kind != VAU_FILE_REGULAR || info.bytes != recovery_files[i].bytes)
			return VAU_DENIED;

		char digest[65];

		rc = vau_upload_file_digest(c, recovery_files[i].path, digest);
		if (rc)
			return rc;
		if (strcmp(digest, recovery_files[i].sha256))
			return VAU_DENIED;
	}

	return VAU_OK;
}

static int snapshot(struct vau_upload_context *c, const char *path, unsigned char *data,
                    size_t *bytes, char digest[65])
{
	if (c->stopped(c->context))
		return VAU_DENIED;

	struct vau_file_chunk chunk;
	int rc = vau_vita_file_read(NULL, path, 0, data, VAU_TAI_CONFIG_BYTES, &chunk);

	if (rc)
		return rc;
	if (chunk.file_bytes > VAU_TAI_CONFIG_BYTES || chunk.count != chunk.file_bytes)
		return VAU_DENIED;

	*bytes = chunk.count;

	unsigned char hash[32];

	rc = mbedtls_sha256(data, *bytes, hash, 0);
	if (rc)
		return VAU_DEVICE_ERROR;

	static const char hex[] = "0123456789abcdef";

	for (unsigned i = 0; i < 32; ++i) {
		digest[i * 2]     = hex[hash[i] >> 4];
		digest[i * 2 + 1] = hex[hash[i] & 15];
	}

	digest[64] = 0;
	return VAU_OK;
}

int vau_config_native_check(struct vau_upload_context *c, const struct vau_write_request *r,
                            const char *before_path, const char *after_path)
{
	if (!c || !c->stopped || !r || !before_path || !after_path || r->operation != VAU_FS_WRITE ||
	    r->overwrite != 1 || r->yes != 1 || !memchr(r->sha256, 0, sizeof(r->sha256)) ||
	    !memchr(r->expected_sha256, 0, sizeof(r->expected_sha256)) ||
	    r->bytes > VAU_TAI_CONFIG_BYTES) {
		return VAU_DENIED;
	}

	unsigned char *data = vauPafMalloc(VAU_TAI_CONFIG_BYTES * 2);

	if (!data)
		return VAU_DEVICE_ERROR;

	size_t before = 0, after = 0;
	char old_hash[65], new_hash[65];
	int rc = snapshot(c, before_path, data, &before, old_hash);

	if (!rc)
		rc = snapshot(c, after_path, data + VAU_TAI_CONFIG_BYTES, &after, new_hash);
	if (!rc && (strcmp(old_hash, r->expected_sha256) || strcmp(new_hash, r->sha256) ||
	            after != r->bytes)) {
		rc = VAU_STALE;
	}

	/* First reject an invalid edit before hashing a recovery executable. */
	if (!rc)
		rc = vau_tai_config_check(data, before, data + VAU_TAI_CONFIG_BYTES, after, 0, 0);
	/* Unknown storage topology is treated as requiring recovery. This avoids
	 * declaring SD2Vita absent from a config file while its driver is loaded.
	 * A trusted native negative storage observation may relax this later. */
	if (!rc)
		rc = vau_config_recovery_copy_check(c);
	if (!rc)
		rc = vau_tai_config_check(data, before, data + VAU_TAI_CONFIG_BYTES, after, 1, 1);
	vauPafFree(data);
	return rc;
}

int vau_config_native_preflight(struct vau_upload_context *c, const struct vau_write_request *r,
                                const char *stage)
{
	return vau_config_native_check(c, r, r->path, stage);
}
