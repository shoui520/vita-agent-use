/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "staged_upload.h"
#include "file_ops.h"
#include "config_native.h"
#include "file_mutations.h"
#include <psp2/io/fcntl.h>
#include <string.h>

#define VAU_IO_ENOENT ((int)0x80010002u)

static int same(const char *a, const char *b)
{
	while (*a && *b) {
		int x = *a, y = *b;

		if (x >= 'A' && x <= 'Z')
			x += 32;
		if (y >= 'A' && y <= 'Z')
			y += 32;
		if (x != y)
			return 0;

		++a;
		++b;
	}

	return !*a && !*b;
}

static int config(const char *p)
{
	return same(p, "ur0:tai/config.txt") || same(p, "ux0:tai/config.txt") ||
	       same(p, "uma0:tai/config.txt");
}

static int backup_path(const struct vau_write_request *r, char out[VAU_PATH_MAX])
{
	int rc = vau_upload_stage_path(r, out);

	if (rc)
		return rc;

	size_t n = strlen(out);

	memcpy(out + n - 5, ".old", 5);
	return VAU_OK;
}

static int observe(struct vau_upload_context *c, const char *path, const char *digest,
                   uint64_t bytes, int check_size, int *exists, int *matches)
{
	*exists = *matches = 0;

	struct vau_file_info info;
	int rc = vau_vita_file_stat(NULL, path, &info);

	if (rc == VAU_IO_ENOENT)
		return VAU_OK;
	if (rc < 0)
		return rc;
	if (info.kind != VAU_FILE_REGULAR)
		return VAU_DENIED;

	*exists = 1;
	if (check_size && info.bytes != bytes)
		return VAU_OK;

	/* Explicit ordinary overwrite may omit an old-content precondition. */
	if (!*digest) {
		*matches = 1;
		return VAU_OK;
	}

	char actual[65];

	rc = vau_upload_file_digest(c, path, actual);
	if (!rc)
		*matches = !strcmp(actual, digest);
	return rc;
}

static int progress(struct vau_upload_context *c, const struct vau_write_request *r,
                    const char *detail, unsigned started)
{
	struct vau_write_record event = { .request        = *r,
		                              .phase          = VAU_WRITE_PROGRESS,
		                              .result         = VAU_BUSY,
		                              .effect_started = started,
		                              .observed_us    = c->clock(c->context) };
	strcpy(event.detail, detail);
	return vau_journal_append(c->journal, &event);
}

static int sync_mount(const char *path)
{
	char mount[9]     = { 0 };
	const char *colon = strchr(path, ':');

	if (!colon || colon - path > 7)
		return VAU_INVALID;

	memcpy(mount, path, (size_t)(colon - path) + 1);

	int rc = sceIoSync(mount, 0);

	return rc < 0 ? rc : VAU_OK;
}

static int lookup(void *context, const char *subject, const char *id, struct vau_write_record *out)
{
	struct vau_upload_context *c = context;

	return vau_journal_lookup(c->journal, subject, id, out);
}

static int audit(void *context, struct vau_write_record *record)
{
	struct vau_upload_context *c = context;

	record->observed_us = c->clock(c->context);
	if (record->phase == VAU_WRITE_INTENT) {
		strcpy(record->effect_path, record->request.path);

		int rc = vau_write_observe(record->effect_path, &record->before);

		if (rc)
			return rc;
	} else if (record->phase == VAU_WRITE_COMPLETE) {
		int rc = vau_write_observe(record->effect_path, &record->after);

		if (!record->result && (rc || record->after.state != VAU_STATE_FILE ||
		                        record->after.bytes != record->request.bytes)) {
			record->phase  = VAU_WRITE_INTENT;
			record->result = VAU_RECOVERY_REQUIRED;
			return VAU_RECOVERY_REQUIRED;
		}
	}

	return vau_journal_append(c->journal, record);
}

static int stop(void *context)
{
	struct vau_upload_context *c = context;

	return c->stopped(c->context);
}

static int preflight(void *context, const struct vau_write_request *r, vau_write_visit visit,
                     void *visit_context)
{
	struct vau_upload_context *c = context;

	if (r->operation != VAU_FS_WRITE)
		return VAU_INVALID;

	int rc = visit(visit_context, r->path);

	if (rc)
		return rc;

	struct vau_upload_status status;

	rc = vau_upload_verify(c, r, &status);
	if (rc)
		return rc;

	int exists, match;

	rc = observe(c, r->path, r->expected_sha256, 0, 0, &exists, &match);
	if (rc)
		return rc;
	if (r->overwrite ? (*r->expected_sha256 && (!exists || !match)) : exists)
		return VAU_STALE;

	char old[VAU_PATH_MAX];

	rc = backup_path(r, old);
	if (rc)
		return rc;

	struct vau_file_info info;

	rc = vau_vita_file_stat(NULL, old, &info);
	return rc == VAU_IO_ENOENT ? VAU_OK : rc < 0 ? rc : VAU_STALE;
}

static int config_check(void *context, const struct vau_write_request *r)
{
	struct vau_upload_context *c = context;
	char stage[VAU_PATH_MAX];

	if (!c->config_check || !c->config_replace)
		return VAU_DENIED;

	int rc = vau_upload_stage_path(r, stage);

	return rc ? rc : c->config_check(c, r, stage);
}

static int apply(void *context, const struct vau_write_request *r, unsigned *started,
                 unsigned *readback)
{
	struct vau_upload_context *c = context;
	char stage[VAU_PATH_MAX], old[VAU_PATH_MAX];

	*started = 0;

	int rc = vau_upload_stage_path(r, stage);

	if (rc)
		return rc;

	rc = backup_path(r, old);
	if (rc)
		return rc;
	if (config(r->path)) {
		*readback = 1;
		rc        = config_check(c, r);
		if (rc)
			return rc;
		if (c->stopped(c->context))
			return VAU_DENIED;
		return c->config_replace(c, r, stage, started);
	}

	int exists, match;

	rc = observe(c, r->path, r->expected_sha256, 0, 0, &exists, &match);
	if (rc)
		return rc;
	if (r->overwrite ? (*r->expected_sha256 && (!exists || !match)) : exists)
		return VAU_STALE;
	if (r->overwrite && exists) {
		rc = progress(c, r, "backup_intent", 0);
		if (rc)
			return rc;
		if (c->stopped(c->context))
			return VAU_DENIED;

		/* Sync namespace changes, not only the stage file's contents. */
		rc       = sceIoRename(r->path, old);
		*started = 1;
		if (rc < 0)
			return VAU_RECOVERY_REQUIRED;

		rc = sync_mount(r->path);
		if (rc)
			return VAU_RECOVERY_REQUIRED;

		rc = progress(c, r, "backup_done", 1);
		if (rc)
			return VAU_RECOVERY_REQUIRED;

		rc = observe(c, old, r->expected_sha256, 0, 0, &exists, &match);
		if (rc || !exists || !match)
			return VAU_RECOVERY_REQUIRED;
	}

	rc = progress(c, r, "install_intent", *started);
	if (rc)
		return *started ? VAU_RECOVERY_REQUIRED : rc;
	if (c->stopped(c->context))
		return *started ? VAU_RECOVERY_REQUIRED : VAU_DENIED;

	rc       = sceIoRename(stage, r->path);
	*started = 1;
	if (rc < 0)
		return VAU_RECOVERY_REQUIRED;

	rc = sync_mount(r->path);
	if (rc)
		return VAU_RECOVERY_REQUIRED;

	rc = progress(c, r, "install_done", 1);
	if (rc)
		return VAU_RECOVERY_REQUIRED;

	rc = observe(c, r->path, r->sha256, r->bytes, 1, &exists, &match);
	return rc || !exists || !match ? VAU_RECOVERY_REQUIRED : VAU_OK;
}

/* Native rename rejects an existing destination. Keep a verified original
 * and stage under the private transaction directory. Only the two native
 * renames occur in the gap; do not wait for network, audit I/O or stop polling
 * while config.txt is absent. This is recoverable, not atomic across power loss. */
int vau_upload_config_replace(struct vau_upload_context *c, const struct vau_write_request *r,
                              const char *stage, unsigned *started)
{
	if (!c || !c->policy || !c->journal || !c->clock || !c->stopped || !r || !stage || !started ||
	    !memchr(r->path, 0, sizeof(r->path)) || !config(r->path) || !r->overwrite) {
		return VAU_INVALID;
	}

	*started = 0;

	char old[VAU_PATH_MAX];
	int rc = backup_path(r, old);

	if (rc)
		return rc;

	char expected_stage[VAU_PATH_MAX];

	rc = vau_upload_stage_path(r, expected_stage);
	if (rc)
		return rc;
	if (strcmp(stage, expected_stage))
		return VAU_DENIED;

	rc = progress(c, r, "config_install_intent", 0);
	if (rc)
		return rc;
	if (c->stopped(c->context))
		return VAU_DENIED;

	rc       = sceIoRename(r->path, old);
	*started = 1;
	if (rc < 0)
		return VAU_RECOVERY_REQUIRED;

	rc = sceIoRename(stage, r->path);
	if (rc < 0) {
		int restored = sceIoRename(old, r->path);

		if (restored < 0 || sync_mount(r->path))
			return VAU_RECOVERY_REQUIRED;

		int exists, match;

		restored = observe(c, r->path, r->expected_sha256, 0, 0, &exists, &match);
		if (restored || !exists || !match)
			return VAU_RECOVERY_REQUIRED;

		restored = progress(c, r, "config_restore_done", 1);
		return restored ? VAU_RECOVERY_REQUIRED : VAU_STALE;
	}

	rc = sync_mount(r->path);
	if (rc)
		return VAU_RECOVERY_REQUIRED;

	rc = progress(c, r, "config_install_done", 1);
	if (rc)
		return VAU_RECOVERY_REQUIRED;

	rc = vau_config_native_check(c, r, old, r->path);
	return rc ? VAU_RECOVERY_REQUIRED : VAU_OK;
}

int vau_upload_commit(struct vau_upload_context *c, const struct vau_write_request *r,
                      struct vau_write_record *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!c || !c->policy || !c->journal || !c->stopped || !c->clock || !r ||
	    r->operation != VAU_FS_WRITE || !memchr(r->path, 0, sizeof(r->path))) {
		return VAU_INVALID;
	}

	if (config(r->path) && (!c->config_check || !c->config_replace))
		return VAU_DENIED;

	struct vau_write_adapter adapter = { .context      = c,
		                                 .lookup       = lookup,
		                                 .audit        = audit,
		                                 .preflight    = preflight,
		                                 .config_check = config_check,
		                                 .apply        = apply,
		                                 .stopped      = stop };
	return vau_write_execute(c->policy, &adapter, r, out);
}

static int local_recovery(void *context)
{
	(void)context;
	return 0;
}

int vau_upload_recover(struct vau_upload_context *c, const struct vau_write_request *r,
                       struct vau_write_record *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!c || !c->policy || !c->journal || !c->clock || !r || r->operation != VAU_FS_WRITE ||
	    !memchr(r->path, 0, sizeof(r->path)) || !memchr(r->subject, 0, sizeof(r->subject)) ||
	    !memchr(r->id, 0, sizeof(r->id)) || !memchr(r->destination, 0, sizeof(r->destination)) ||
	    !memchr(r->sha256, 0, sizeof(r->sha256)) ||
	    !memchr(r->expected_sha256, 0, sizeof(r->expected_sha256))) {
		return VAU_INVALID;
	}

	int rc = vau_journal_lookup(c->journal, r->subject, r->id, out);

	if (rc)
		return rc == 1 ? VAU_STALE : rc;
	if (!vau_write_request_same(&out->request, r))
		return VAU_STALE;
	if (out->phase == VAU_WRITE_COMPLETE)
		return out->result;

	int is_config = config(r->path);

	if (is_config && (!c->config_check || !c->config_replace))
		return VAU_RECOVERY_REQUIRED;

	/* Trusted reconciliation may restore the old file after a stop or ACL
	 * revocation, but absolute path/plugin protections still apply. Never
	 * accept a peer-provided bypass; authority is the bound durable intent. */
	struct vau_file_policy policy = { .active_tai = c->policy->active_tai, .count = 1 };

	/* A missing ux0 config can select ur0 fallback. The validated intent,
	 * rather than that temporary precedence, binds the root being restored. */
	if (is_config && out->phase == VAU_WRITE_INTENT && out->readback_required) {
		policy.active_tai = same(r->path, "ur0:tai/config.txt")   ? VAU_TAI_UR0
		                    : same(r->path, "ux0:tai/config.txt") ? VAU_TAI_UX0
		                                                          : VAU_TAI_UMA0;
	}

	strcpy(policy.rules[0].subject, r->subject);
	strcpy(policy.rules[0].path, r->path);
	policy.rules[0].allow = VAU_ACL_ALL;
	if (vau_policy_evaluate(&policy, r->subject, VAU_FS_WRITE, r->path, 1) != VAU_POLICY_ALLOW)
		return VAU_DENIED;

	struct vau_upload_context recovery = *c;

	recovery.stopped = local_recovery;

	char stage[VAU_PATH_MAX], old[VAU_PATH_MAX];

	rc = vau_upload_stage_path(r, stage);
	if (rc)
		return rc;

	rc = backup_path(r, old);
	if (rc)
		return rc;

	int se, sm, oe, om, te, tm;

	rc = observe(&recovery, stage, r->sha256, r->bytes, 1, &se, &sm);
	if (rc)
		return rc;

	rc = observe(&recovery, old, r->expected_sha256, 0, 0, &oe, &om);
	if (rc)
		return rc;

	rc = observe(&recovery, r->path, r->sha256, r->bytes, 1, &te, &tm);
	if (rc)
		return rc;

	int result      = VAU_RECOVERY_REQUIRED;
	unsigned effect = 0;

	if (!se && te && tm && (!r->overwrite || !*r->expected_sha256 || (oe && om))) {
		if (is_config) {
			rc = vau_config_native_check(&recovery, r, old, r->path);
			if (rc)
				return VAU_RECOVERY_REQUIRED;
		}

		result = VAU_OK;
		effect = 1;
	} else if (!te && oe && om && r->overwrite) {
		rc = progress(&recovery, r, "restore_intent", 1);
		if (rc)
			return rc;

		rc = sceIoRename(old, r->path);
		if (rc < 0)
			return VAU_RECOVERY_REQUIRED;

		rc = sync_mount(r->path);
		if (rc)
			return VAU_RECOVERY_REQUIRED;

		int restored_exists, restored_matches;

		rc = observe(&recovery, r->path, r->expected_sha256, 0, 0, &restored_exists,
		             &restored_matches);
		if (rc || !restored_exists || !restored_matches)
			return VAU_RECOVERY_REQUIRED;

		rc = progress(&recovery, r, "restore_done", 1);
		if (rc)
			return rc;

		result = VAU_STALE;
		effect = 1;
	} else if (se && sm && !oe) {
		int original_exists, original_matches;

		rc = observe(&recovery, r->path, r->expected_sha256, 0, 0, &original_exists,
		             &original_matches);
		if (rc)
			return rc;
		if (r->overwrite ? original_exists && original_matches : !original_exists)
			result = VAU_STALE;
	}

	if (result == VAU_RECOVERY_REQUIRED)
		return result;

	rc = sync_mount(r->path);
	if (rc)
		return VAU_RECOVERY_REQUIRED;

	rc = vau_write_observe(r->path, &out->after);
	if (rc)
		return VAU_RECOVERY_REQUIRED;
	if (!out->effect_path[0])
		strcpy(out->effect_path, r->path);
	out->phase          = VAU_WRITE_COMPLETE;
	out->result         = result;
	out->effect_started = effect;
	if (is_config)
		out->readback_required = 1;
	out->observed_us = c->clock(c->context);
	strcpy(out->detail, result == VAU_OK ? "recovered_install" : "recovered_restore");
	rc = vau_journal_append(c->journal, out);
	return rc ? rc : result;
}
