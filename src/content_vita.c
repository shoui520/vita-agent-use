/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_runtime.h"
#include "acl_vita.h"
#include "content_delete.h"
#include "content_scope.h"
#include "native_ops.h"
#include "content_media_capture_vita.h"
#include "content_sdk.h"
#include "format.h"
#include "writes_vita.h"
#include <string.h>

static struct {
	struct vau_service *service;
	struct vau_content_journal journal;
	struct vau_content_runtime runtime;
	struct vau_content_approval approval;
	struct vau_content_worker worker;
	struct vau_content_sdk sdk;
	struct vau_content_capture_native capture, after_capture;
	struct vau_media_capture_vita media;
	uint64_t handle, generation, audit_scope;
	struct vau_content_delete_request audit_request;
	struct vau_content_delete_request request;
	unsigned savedata_user;
	int initialized;
} content;

static uint64_t clock_now(void *ctx)
{
	(void)ctx;
	return vau_vita_native_api.clock(vau_vita_native_api.context);
}

static int authorized(void *ctx, const struct vau_content_delete_request *request)
{
	(void)ctx;
	if (!content.service || content.service->auth.stopped ||
	    content.generation != content.service->auth.stop_generation) {
		return VAU_DENIED;
	}

	uint64_t now = clock_now(NULL);

	for (unsigned i = 0; i < VAU_AUTH_SLOTS; i++) {
		const struct vau_auth_entry *entry = &content.service->auth.entries[i];

		if (content.handle && entry->handle == content.handle && now < entry->expires_us &&
		    (entry->session.rights & VAU_RIGHT_CONTROL) &&
		    !strcmp(entry->session.subject, request->subject)) {
			return 0;
		}
	}

	return VAU_DENIED;
}

static int stopped(void *ctx)
{
	(void)ctx;
	return authorized(NULL, &content.request) != 0;
}

static int read_policy(void *ctx, struct vau_file_policy *out)
{
	(void)ctx;
	return vau_vita_acl_load(out);
}

static int media_capture(void *ctx, struct vau_content_scope_writer *w,
                         const struct vau_file_policy *policy,
                         const struct vau_content_capture_adapter *adapter)
{
	(void)ctx;

	/* Retry release of previously owned read-only resources before reopening. */
	int rc = vau_vita_media_capture_cleanup(&content.media);

	return rc ? rc : vau_vita_media_capture(&content.media, w, policy, 0, adapter);
}

static int metadata(void *ctx, const char *title, struct vau_app_install_metadata *out, int *shared)
{
	(void)ctx;

	int rc = vau_app_registry_install_metadata("ur0:shell/db/app.db", title, out);

	if (rc)
		return rc == 1 ? VAU_STALE : rc;

	*shared = 0;
	if ((out->present & 1) && !strncmp(out->values[0], "ux0:pspemu/PSP/GAME/", 20))
		return vau_app_registry_gamedata("ur0:shell/db/app.db", title, out->gamedata_id, shared);
	if ((out->present & 2) && out->values[1][0]) {
		return vau_app_registry_savedata_shared("ur0:shell/db/app.db", title, out->values[1],
		                                        shared);
	}

	return 0;
}

static int inspect(void *ctx, const char *title, struct vau_content_observation *out)
{
	(void)ctx;

	struct vau_app_entry entry;
	int rc = vau_app_registry_find("ur0:shell/db/app.db", title, &entry);

	if (rc < 0)
		return rc;

	struct vau_content_observation found = { .registered = rc == 0 };

	/* Registration may already be gone after SDK execution. Observe the
	 * immutable reviewed origin, rather than inventing ux0:app/TITLEID. */
	const struct vau_app_install_metadata *m = &content.runtime.reviewed_metadata;

	if (!content.runtime.reviewed || strcmp(title, content.request.title) || !(m->present & 1) ||
	    !memchr(m->values[0], 0, sizeof(m->values[0]))) {
		return VAU_STALE;
	}

	const char *path = m->values[0];
	struct vau_file_info info;

	rc = vau_vita_file_stat(NULL, path, &info);
	if (rc && rc != (int)0x80010002u)
		return rc;
	if (!rc && info.kind != VAU_FILE_DIRECTORY)
		return VAU_STALE;

	found.application_present = rc == 0;
	*out                      = found;
	return 0;
}

static int approval_begin(void *ctx, const struct vau_content_delete_request *request, int shared)
{
	(void)ctx;
	content.approval.handle          = content.handle;
	content.approval.shared_savedata = shared;
	content.approval.legacy_application =
	        !strncmp(content.runtime.reviewed_metadata.values[0], "ux0:pspemu/PSP/GAME/", 20);
	return vau_content_approval_begin(&content.approval, request);
}

static int approval_poll(void *ctx)
{
	(void)ctx;
	return vau_content_approval_poll(&content.approval);
}

static int approval_finish(void *ctx)
{
	(void)ctx;
	return vau_content_approval_finish(&content.approval);
}

static int execute_savedata(void *ctx, const char *title)
{
	return vau_content_sdk_remove_savedata(ctx, title, content.savedata_user);
}

static int savedata_backup(void *ctx, unsigned user, const char *save,
                           struct vau_savedata_backup *out)
{
	(void)ctx;
	return vau_vita_savedata_backup(user, save, stopped, NULL, out);
}

static int native_start(void *ctx, const struct vau_content_delete_request *request)
{
	(void)ctx;
	if (!vau_content_delete_target_same(request, &content.request))
		return VAU_STALE;
	if (content.worker.thread >= 0 ||
	    atomic_load_explicit(&content.worker.done, memory_order_acquire)) {
		return VAU_BUSY;
	}

	int rc = vau_content_legacy_reset();

	if (rc < 0)
		return rc;
	if (request->kind == VAU_CONTENT_VITA_SAVEDATA) {
		content.savedata_user = request->user;
		return vau_content_worker_start(&content.worker, request->title, execute_savedata,
		                                &content.sdk);
	}

	return vau_content_worker_start(&content.worker, request->title, vau_content_sdk_delete,
	                                &content.sdk);
}

static int native_poll(void *ctx, int *result)
{
	(void)ctx;
	return vau_content_worker_poll(&content.worker, result);
}

void vau_vita_content_init(struct vau_service *service)
{
	/* Called once at service-thread startup; never initialize Sony's SDK or
	 * open databases while Shell is booting. */
	memset(&content, 0, sizeof(content));
	content.service = service;
	vau_content_worker_init(&content.worker);
	vau_vita_content_sdk_init(&content.sdk);
	vau_content_approval_init(&content.approval, service, &vau_vita_native_api);
	content.capture.stopped = stopped;
	vau_vita_media_capture_init(&content.media, NULL, stopped);

	struct vau_content_runtime_io io = { .clock           = clock_now,
		                                 .authorized      = authorized,
		                                 .policy          = read_policy,
		                                 .metadata        = metadata,
		                                 .media_capture   = media_capture,
		                                 .inspect         = inspect,
		                                 .approval_begin  = approval_begin,
		                                 .approval_poll   = approval_poll,
		                                 .approval_finish = approval_finish,
		                                 .native_start    = native_start,
		                                 .savedata_backup = savedata_backup,
		                                 .native_poll     = native_poll };
	vau_content_capture_native_adapter(&io.capture, &content.capture);
	vau_content_capture_native_adapter(&io.after_capture, &content.after_capture);
	content.initialized = !vau_content_runtime_init(&content.runtime, &content.journal, &io);
}

static int open_journal(void)
{
	if (!content.initialized)
		return VAU_DENIED;
	return content.journal.db
	               ? 0
	               : vau_content_journal_open(&content.journal,
	                                          "ur0:data/vita-agent-use/content-audit.db", 0);
}

int vau_vita_content_busy(void)
{
	return content.initialized &&
	       (vau_content_runtime_busy(&content.runtime) || content.worker.thread >= 0 ||
	        atomic_load_explicit(&content.worker.done, memory_order_acquire));
}

int vau_vita_content_promote(const char *path)
{
	return content.initialized ? vau_content_sdk_promote(&content.sdk, path) : VAU_DENIED;
}

int vau_vita_content_inflight(void)
{
	return content.initialized &&
	       (content.worker.thread >= 0 ||
	        atomic_load_explicit(&content.worker.done, memory_order_acquire));
}

int vau_vita_content_submit(uint64_t handle, const struct vau_content_delete_request *request,
                            struct vau_content_delete_record *out)
{
	if (!out || !vau_content_delete_request_valid(request) || !content.initialized)
		return VAU_INVALID;
	if (vau_vita_content_busy() &&
	    (strcmp(request->subject, content.runtime.job.record.request.subject) ||
	     strcmp(request->id, content.runtime.job.record.request.id))) {
		return VAU_BUSY;
	}

	/* Never allow a second authenticated identity to replace the approval's
	 * original handle or stop generation, including on a replay. */
	if (!vau_vita_content_busy()) {
		content.handle     = handle;
		content.generation = content.service->auth.stop_generation;
		content.request    = *request;
	}

	if (vau_vita_approval_pending(NULL) && !vau_vita_content_busy())
		return VAU_BUSY;

	int rc = authorized(NULL, request);

	if (!rc)
		rc = open_journal();
	if (!rc)
		rc = vau_content_runtime_submit(&content.runtime, request);
	if (!rc)
		*out = content.runtime.job.record;
	return rc;
}

int vau_vita_content_status(const char *subject, const char *id,
                            struct vau_content_delete_record *out)
{
	if (!subject || !id || !out)
		return VAU_INVALID;

	int rc = open_journal();

	if (rc)
		return rc;
	return vau_content_journal_lookup(&content.journal, subject, id, out);
}

void vau_vita_approval_poll(void *ctx)
{
	vau_vita_acl_poll(ctx);
	if (!content.initialized)
		return;
	if (content.journal.db && vau_content_runtime_busy(&content.runtime))
		(void)vau_content_runtime_poll(&content.runtime);
	/* A failed start/cleanup can leave a completed thread owned even after
	 * the operation became UNCERTAIN. Reclaim it, never start it again. */
	if (content.runtime.job.record.state != VAU_CONTENT_DELETE_RUNNING &&
	    vau_vita_content_inflight()) {
		int result;

		(void)vau_content_worker_poll(&content.worker, &result);
	}
}

void vau_vita_approval_cancel(void *ctx)
{
	vau_vita_acl_cancel(ctx);
	if (content.initialized)
		vau_content_approval_cancel(&content.approval);
}

int vau_vita_approval_pending(void *ctx)
{
	return vau_vita_acl_pending(ctx);
}

static int status_json(const struct vau_content_delete_record *record, int persisted, char *out,
                       size_t cap)
{
	char base[768];
	int n = vau_content_record_json(record, persisted, base, sizeof(base));

	if (n < 0)
		return n;

	struct vau_content_scope scope;
	uint64_t before = 0, after = 0;
	int rc = vau_content_scope_latest(&content.journal, &record->request, VAU_CONTENT_SCOPE_BEFORE,
	                                  &scope);

	if (!rc)
		before = scope.sequence;
	else if (rc != 1)
		return rc;

	rc = vau_content_scope_latest(&content.journal, &record->request, VAU_CONTENT_SCOPE_AFTER,
	                              &scope);
	if (!rc)
		after = scope.sequence;
	else if (rc != 1)
		return rc;

	n = vau_snprintf(out, cap, "%.*s,\"before_scope\":\"%llu\",\"after_scope\":\"%llu\"}", n - 1,
	                 base, (unsigned long long)before, (unsigned long long)after);
	return n < 0 || (size_t)n >= cap ? VAU_UNSUPPORTED : n;
}

int vau_vita_content_query(void *ctx, uint64_t handle, const char *subject,
                           const struct vau_content_query *q, char *out, size_t cap)
{
	(void)ctx;
	if (!content.initialized || !q || !out || !cap || !subject || strlen(subject) != 64 ||
	    q->operation > VAU_CONTENT_ALBUMS) {
		return VAU_INVALID;
	}

	unsigned right = (q->operation == VAU_CONTENT_PREVIEW || q->operation == VAU_CONTENT_REQUEST)
	                         ? VAU_RIGHT_CONTROL
	                         : VAU_RIGHT_OBSERVE;
	int live       = 0;
	uint64_t now   = clock_now(NULL);

	if (content.service->auth.stopped)
		return VAU_DENIED;

	for (unsigned i = 0; i < VAU_AUTH_SLOTS; i++) {
		const struct vau_auth_entry *e = &content.service->auth.entries[i];

		if (handle && e->handle == handle && now < e->expires_us && (e->session.rights & right) &&
		    !strcmp(e->session.subject, subject)) {
			live = 1;
		}
	}

	if (!live)
		return VAU_DENIED;

	int rc = open_journal();

	if (rc)
		return rc;
	if (q->operation == VAU_CONTENT_AUDIT)
		return vau_content_audit_json(&content.journal, q->cursor, out, cap);
	if (q->operation == VAU_CONTENT_REQUEST) {
		if (q->yes != 1 || !q->before)
			return VAU_DENIED;
		if (cap < 1024)
			return VAU_INVALID;

		struct vau_content_delete_request request = {
			.yes = 1, .preview_sequence = q->before, .kind = q->kind, .user = q->user
		};

		memcpy(request.subject, subject, 65);
		memcpy(request.id, q->id, sizeof(request.id));
		memcpy(request.title, q->title, sizeof(request.title));

		struct vau_content_delete_record record;

		rc = vau_vita_content_submit(handle, &request, &record);
		if (rc)
			return rc;
		return status_json(&record, !content.runtime.job.needs_persist, out, cap);
	}

	if (q->operation == VAU_CONTENT_STATUS) {
		struct vau_content_delete_record record;
		int persisted = 1;

		if (!strcmp(subject, content.runtime.job.record.request.subject) &&
		    !strcmp(q->id, content.runtime.job.record.request.id)) {
			record    = content.runtime.job.record;
			persisted = !content.runtime.job.needs_persist;
			if (content.runtime.after)
				record.scope_sequence = content.runtime.after;
			else if (content.runtime.before)
				record.scope_sequence = content.runtime.before;
			else if (content.runtime.preview)
				record.scope_sequence = content.runtime.preview;
		} else {
			rc = vau_content_journal_lookup(&content.journal, subject, q->id, &record);
			if (rc)
				return rc == 1 ? VAU_STALE : rc;
		}

		return status_json(&record, persisted, out, cap);
	}

	if (q->operation == VAU_CONTENT_PREVIEW) {
		if (vau_vita_content_busy() || vau_vita_approval_pending(NULL))
			return VAU_BUSY;

		struct vau_content_delete_request request = {
			.yes = 1, .kind = q->kind, .user = q->user, .media_id = q->media_id
		};

		memcpy(request.subject, subject, 65);
		memcpy(request.id, q->id, sizeof(request.id));
		memcpy(request.title, q->title, sizeof(request.title));
		content.handle     = handle;
		content.generation = content.service->auth.stop_generation;
		content.request    = request;

		struct vau_content_scope scope;

		rc = vau_content_runtime_preview(&content.runtime, &request, &scope);
		if (rc)
			return rc;

		char target[64];

		rc = vau_content_target_json(&request, target, sizeof(target));
		if (rc < 0)
			return rc;

		char title[16] = "null";

		if (request.kind < VAU_CONTENT_PHOTO)
			vau_snprintf(title, sizeof(title), "\"%s\"", request.title);

		int n = vau_snprintf(
		        out, cap,
		        "{\"operation_id\":\"%s\",\"title_id\":%s%s,\"before_scope\":\"%llu\","
		        "\"after_scope\":\"0\",\"path_count\":\"%llu\",\"observed_us\":\"%llu\","
		        "\"execution_started\":false%s}",
		        request.id, title, target, (unsigned long long)scope.sequence,
		        (unsigned long long)scope.path_count, (unsigned long long)scope.observed_us,
		        request.kind >= VAU_CONTENT_PHOTO ? ",\"execution_supported\":false" : "");

		return n < 0 || (size_t)n >= cap ? VAU_UNSUPPORTED : n;
	}

	struct vau_content_scope scope;

	rc = vau_content_scope_get(&content.journal, q->before, &scope);
	if (rc)
		return rc == 1 ? VAU_STALE : rc;
	if (strcmp(scope.request.id, q->id))
		return VAU_DENIED;
	if (strcmp(scope.request.subject, subject)) {
		/* Observe grants may synchronize prior agents' durable audit scopes.
		 * An unanchored preview stays private to its requesting identity. */
		if (q->operation != VAU_CONTENT_SCOPE && q->operation != VAU_CONTENT_ALBUMS)
			return VAU_DENIED;
		if (content.audit_scope != q->before ||
		    strcmp(content.audit_request.subject, scope.request.subject) ||
		    strcmp(content.audit_request.id, scope.request.id) ||
		    strcmp(content.audit_request.title, scope.request.title)) {
			struct vau_content_delete_record anchor;

			rc = vau_content_journal_scope_lookup(&content.journal, q->before, &anchor);
			if (rc)
				return rc == 1 ? VAU_DENIED : rc;

			/* Immutable committed scopes: validate the durable anchor once per
			 * streamed scope, rather than recounting every path per chunk. */
			content.audit_scope   = q->before;
			content.audit_request = scope.request;
		}
	}

	if (q->operation == VAU_CONTENT_ALBUMS) {
		return vau_content_albums_json(&content.journal, &scope.request, q->before, q->cursor,
		                               q->after, out, cap);
	}

	if (q->operation == VAU_CONTENT_SCOPE) {
		return vau_content_snapshot_json(&content.journal, &scope.request, q->before, q->cursor,
		                                 out, cap);
	}

	return vau_content_changes_json(&content.journal, &scope.request, q->before, q->after,
	                                q->cursor, out, cap);
}
