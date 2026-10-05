/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_runtime.h"
#include "format.h"
#include <string.h>

static uint64_t clock_now(void *ctx)
{
	struct vau_content_runtime *r = ctx;

	return r->io.clock(r->io.context);
}

static int lookup(void *ctx, const char *subject, const char *id,
                  struct vau_content_delete_record *out)
{
	struct vau_content_runtime *r = ctx;

	return vau_content_journal_lookup(r->journal, subject, id, out);
}

static int persist(void *ctx, const struct vau_content_delete_record *record)
{
	struct vau_content_runtime *r = ctx;
	uint64_t scope                = r->after ? r->after : r->before ? r->before : r->preview;

	if (!scope)
		scope = record->scope_sequence; /* Durable replay; never execute again. */
	int rc = vau_content_journal_persist_scope(r->journal, record, scope);

	if (!rc)
		r->job.record.scope_sequence = scope;
	return rc;
}

static int plan_only(void *ctx, const char *path, enum vau_content_path_role role)
{
	(void)ctx;
	(void)path;
	(void)role;
	return 0;
}

static int backup(struct vau_content_runtime *r, const struct vau_content_delete_request *request,
                  const struct vau_app_install_metadata *metadata, struct vau_savedata_backup *out)
{
	if (!r->io.savedata_backup)
		return VAU_UNSUPPORTED;

	int rc =
	        vau_content_plan_savedata(request->title, metadata, request->user, "", plan_only, NULL);

	if (!rc)
		rc = r->io.savedata_backup(r->io.context, request->user, metadata->values[1], out);
	if (rc)
		return rc;
	if (!memchr(out->filename, 0, sizeof(out->filename)) || out->found > 1 ||
	    out->directory_present > 1 || out->found != (out->filename[0] != 0) ||
	    (out->found && !out->directory_present) ||
	    (out->directory_present && out->directory.kind != VAU_FILE_DIRECTORY) ||
	    (out->found && out->file.kind != VAU_FILE_REGULAR)) {
		return VAU_DEVICE_ERROR;
	}

	return vau_content_plan_savedata(request->title, metadata, request->user, out->filename,
	                                 plan_only, NULL);
}

static int same_info(const struct vau_file_info *a, const struct vau_file_info *b)
{
	return a->bytes == b->bytes && a->mode == b->mode && a->attributes == b->attributes &&
	       a->kind == b->kind && a->year == b->year && a->month == b->month && a->day == b->day &&
	       a->hour == b->hour && a->minute == b->minute && a->second == b->second &&
	       a->microsecond == b->microsecond;
}

static int same_backup(const struct vau_savedata_backup *a, const struct vau_savedata_backup *b)
{
	return a->found == b->found && a->directory_present == b->directory_present &&
	       !strcmp(a->filename, b->filename) &&
	       (!a->directory_present || same_info(&a->directory, &b->directory)) &&
	       (!a->found || same_info(&a->file, &b->file));
}

static int capture(struct vau_content_runtime *r, const struct vau_content_delete_request *request,
                   enum vau_content_scope_phase phase, uint64_t *out)
{
	struct vau_content_scope_writer writer = { 0 };
	int rc = vau_content_scope_begin(&writer, r->journal, request, phase, clock_now(r));

	if (!rc) {
		if (phase == VAU_CONTENT_SCOPE_AFTER) {
			rc = vau_content_capture_after(&writer, r->before, &r->io.after_capture);
		} else if (request->kind == VAU_CONTENT_VITA_SAVEDATA) {
			rc = vau_content_capture_savedata(&writer, &r->reviewed_policy, &r->reviewed_metadata,
			                                  request->user, r->reviewed_backup.filename,
			                                  &r->io.capture);
		} else {
			rc = vau_content_capture_vita(&writer, &r->reviewed_policy, &r->reviewed_metadata,
			                              r->shared, &r->io.capture);
		}
	}

	if (!rc)
		rc = vau_content_scope_commit(&writer);
	if (rc && writer.journal) {
		int aborted = vau_content_scope_abort(&writer);

		if (aborted)
			return aborted;
	}

	if (!rc)
		*out = writer.scope.sequence;
	return rc;
}

/* SQL compares immutable path sets, without allocating a directory-sized
 * array. Physical approval never authorizes paths added after the preview. */
static int reviewed_paths(struct vau_content_runtime *r, uint64_t current, uint64_t reviewed)
{
	sqlite3_stmt *s = NULL;
	int rc          = sqlite3_prepare_v2(
            r->journal->db,
            "SELECT 1 FROM content_scope_paths a WHERE a.scope_sequence=CAST(?1 AS INTEGER) "
	                 "AND NOT EXISTS(SELECT 1 FROM content_scope_paths b WHERE "
	                 "b.scope_sequence=CAST(?2 AS INTEGER) AND b.path=a.path AND b.role=a.role "
	                 "AND b.is_root=a.is_root) LIMIT 1",
            -1, &s, NULL);
	char before[24], preview[24];

	vau_snprintf(before, sizeof(before), "%llu", (unsigned long long)current);
	vau_snprintf(preview, sizeof(preview), "%llu", (unsigned long long)reviewed);
	if (!rc)
		rc = sqlite3_bind_text(s, 1, before, -1, NULL);
	if (!rc)
		rc = sqlite3_bind_text(s, 2, preview, -1, NULL);
	if (!rc) {
		int step = sqlite3_step(s);

		rc = step == 101 ? 0 : step == 100 ? VAU_STALE : -65536 - step;
	} else {
		rc = -65536 - rc;
	}

	if (s) {
		int end = sqlite3_finalize(s);

		if (!rc && end)
			rc = -65536 - end;
	}

	return rc;
}

static int allowed(void *ctx, const struct vau_content_delete_request *request)
{
	struct vau_content_runtime *r = ctx;
	int rc                        = r->io.authorized(r->io.context, request);

	if (rc)
		return rc;

	struct vau_file_policy policy            = { 0 };
	struct vau_app_install_metadata metadata = { 0 };
	int shared                               = 0;

	rc = r->io.policy(r->io.context, &policy);
	if (!rc)
		rc = r->io.metadata(r->io.context, request->title, &metadata, &shared);

	struct vau_savedata_backup selected = { 0 };

	if (!rc && request->kind == VAU_CONTENT_VITA_SAVEDATA)
		rc = backup(r, request, &metadata, &selected);
	if (rc)
		return rc;
	if (r->reviewed) {
		if (memcmp(&policy, &r->reviewed_policy, sizeof(policy)) ||
		    memcmp(&metadata, &r->reviewed_metadata, sizeof(metadata)) || shared != r->shared ||
		    (request->kind == VAU_CONTENT_VITA_SAVEDATA &&
		     !same_backup(&selected, &r->reviewed_backup))) {
			return VAU_STALE;
		}

		r->ready_before = 1;
		return 0;
	}

	r->reviewed_policy   = policy;
	r->reviewed_metadata = metadata;
	r->reviewed_backup   = selected;
	r->shared            = shared;
	rc                   = capture(r, request, VAU_CONTENT_SCOPE_PREVIEW, &r->preview);
	if (!rc && request->preview_sequence) {
		struct vau_content_scope approved;

		rc = vau_content_scope_get(r->journal, request->preview_sequence, &approved);
		if (rc == 1)
			rc = VAU_STALE;
		if (!rc && (approved.phase != VAU_CONTENT_SCOPE_PREVIEW ||
		            !vau_content_delete_target_same(&approved.request, request))) {
			rc = VAU_STALE;
		}

		if (!rc)
			rc = reviewed_paths(r, r->preview, request->preview_sequence);
	}

	if (!rc)
		r->reviewed = 1;
	return rc;
}

static int inspect(void *ctx, const struct vau_content_delete_request *request,
                   struct vau_content_observation *out)
{
	struct vau_content_runtime *r = ctx;
	int after                     = r->job.record.state == VAU_CONTENT_DELETE_RUNNING;

	/* Gather the audit even when the registration lookup fails after effect. */
	int rc = 0;

	if (after) {
		rc = capture(r, request, VAU_CONTENT_SCOPE_AFTER, &r->after);
		if (!rc) {
			struct vau_content_scope_page page;
			uint64_t cursor = 0;

			do {
				rc = vau_content_scope_page(r->journal, r->after, cursor, &page);
				if (rc)
					break;

				for (unsigned i = 0; i < page.count; i++) {
					if (page.entries[i].observation.state == VAU_STATE_UNKNOWN) {
						rc = page.entries[i].observation.error;
						break;
					}
				}

				cursor = page.next;
			} while (!rc && page.more);
		}
	} else if (r->ready_before) {
		rc = capture(r, request, VAU_CONTENT_SCOPE_BEFORE, &r->before);
		if (!rc)
			rc = reviewed_paths(r, r->before, r->preview);
		if (!rc)
			rc = r->io.authorized(r->io.context, request);
	}

	if (rc)
		return rc;

	struct vau_content_observation found = { 0 };

	rc = r->io.inspect(r->io.context, request->title, &found);
	if (!rc)
		*out = found;
	return rc;
}

static int approval_begin(void *ctx, const struct vau_content_delete_request *request)
{
	struct vau_content_runtime *r = ctx;

	return r->io.approval_begin(r->io.context, request, r->shared);
}

#define FORWARD(name)                        \
	static int name(void *ctx)               \
	{                                        \
		struct vau_content_runtime *r = ctx; \
		return r->io.name(r->io.context);    \
	}
FORWARD(approval_poll)
FORWARD(approval_finish)

static int native_start(void *ctx, const struct vau_content_delete_request *request)
{
	struct vau_content_runtime *r = ctx;
	int rc                        = allowed(r, &r->job.record.request);

	return rc ? rc : r->io.native_start(r->io.context, request);
}

static int savedata_complete(void *ctx, const struct vau_content_delete_request *request)
{
	struct vau_content_runtime *r = ctx;

	if (!vau_content_delete_target_same(request, &r->job.record.request))
		return VAU_STALE;
	return vau_content_scope_savedata_complete(r->journal, r->before, r->after);
}

static int native_poll(void *ctx, int *result)
{
	struct vau_content_runtime *r = ctx;

	return r->io.native_poll(r->io.context, result);
}

static struct vau_content_delete_adapter adapter(struct vau_content_runtime *r)
{
	return (struct vau_content_delete_adapter){ r,
		                                        clock_now,
		                                        lookup,
		                                        persist,
		                                        inspect,
		                                        allowed,
		                                        approval_begin,
		                                        approval_poll,
		                                        approval_finish,
		                                        native_start,
		                                        native_poll,
		                                        r->io.savedata_backup ? savedata_complete : NULL };
}

int vau_content_runtime_init(struct vau_content_runtime *r, struct vau_content_journal *j,
                             const struct vau_content_runtime_io *io)
{
	if (!r || !j || !io || !io->clock || !io->authorized || !io->policy || !io->metadata ||
	    !io->inspect || !io->approval_begin || !io->approval_poll || !io->approval_finish ||
	    !io->native_start || !io->native_poll || !io->capture.observe || !io->capture.walk ||
	    !io->capture.stopped || !io->after_capture.observe || !io->after_capture.walk) {
		return VAU_INVALID;
	}

	memset(r, 0, sizeof(*r));
	r->journal = j;
	r->io      = *io;
	return 0;
}

int vau_content_runtime_busy(const struct vau_content_runtime *r)
{
	return r && (r->job.record.state == VAU_CONTENT_DELETE_APPROVAL ||
	             r->job.record.state == VAU_CONTENT_DELETE_RUNNING || r->job.needs_persist);
}

int vau_content_runtime_submit(struct vau_content_runtime *r,
                               const struct vau_content_delete_request *request)
{
	if (!r || !r->journal || !r->journal->db || !vau_content_delete_request_valid(request))
		return VAU_INVALID;
	if (request->kind >= VAU_CONTENT_PHOTO)
		return VAU_UNSUPPORTED;
	if (request->kind == VAU_CONTENT_VITA_SAVEDATA && !r->io.savedata_backup)
		return VAU_UNSUPPORTED;
	if (strcmp(r->job.record.request.subject, request->subject) ||
	    strcmp(r->job.record.request.id, request->id)) {
		if (vau_content_runtime_busy(r))
			return VAU_BUSY;

		r->preview = r->before = r->after = r->retry_after_us = 0;
		r->reviewed = r->ready_before = r->shared = 0;
	}

	struct vau_content_delete_adapter a = adapter(r);

	return vau_content_delete_submit(&r->job, &a, request);
}

int vau_content_runtime_poll(struct vau_content_runtime *r)
{
	if (!r || !r->journal || !r->journal->db)
		return VAU_INVALID;

	uint64_t now = clock_now(r);

	if (r->job.needs_persist && now < r->retry_after_us)
		return VAU_BUSY;

	struct vau_content_delete_adapter a = adapter(r);
	int rc                              = vau_content_delete_poll(&r->job, &a);

	r->retry_after_us =
	        r->job.needs_persist ? now > UINT64_MAX - 1000000 ? UINT64_MAX : now + 1000000 : 0;
	return rc;
}

int vau_content_runtime_preview(struct vau_content_runtime *r,
                                const struct vau_content_delete_request *request,
                                struct vau_content_scope *out)
{
	if (!r || !r->journal || !r->journal->db || !out || !vau_content_delete_request_valid(request))
		return VAU_INVALID;
	if (request->kind >= VAU_CONTENT_PHOTO && !r->io.media_capture)
		return VAU_UNSUPPORTED;
	if (request->kind == VAU_CONTENT_VITA_SAVEDATA && !r->io.savedata_backup)
		return VAU_UNSUPPORTED;
	if (vau_content_runtime_busy(r))
		return VAU_BUSY;

	int rc = r->io.authorized(r->io.context, request);

	if (rc)
		return rc;

	struct vau_content_delete_record existing;

	rc = vau_content_journal_lookup(r->journal, request->subject, request->id, &existing);
	if (rc != 1)
		return rc ? rc : VAU_STALE;

	struct vau_file_policy policy            = { 0 };
	struct vau_app_install_metadata metadata = { 0 };
	int shared                               = 0;

	rc = r->io.policy(r->io.context, &policy);
	if (!rc && request->kind < VAU_CONTENT_PHOTO)
		rc = r->io.metadata(r->io.context, request->title, &metadata, &shared);

	struct vau_savedata_backup selected = { 0 };

	if (!rc && request->kind == VAU_CONTENT_VITA_SAVEDATA)
		rc = backup(r, request, &metadata, &selected);

	struct vau_content_scope_writer writer = { 0 };

	if (!rc) {
		rc = vau_content_scope_begin(&writer, r->journal, request, VAU_CONTENT_SCOPE_PREVIEW,
		                             clock_now(r));
	}

	if (!rc) {
		if (request->kind >= VAU_CONTENT_PHOTO) {
			rc = r->io.media_capture(r->io.context, &writer, &policy, &r->io.capture);
		} else if (request->kind == VAU_CONTENT_VITA_SAVEDATA) {
			rc = vau_content_capture_savedata(&writer, &policy, &metadata, request->user,
			                                  selected.filename, &r->io.capture);
		} else {
			rc = vau_content_capture_vita(&writer, &policy, &metadata, shared, &r->io.capture);
		}
	}

	if (!rc)
		rc = vau_content_scope_commit(&writer);
	if (rc && writer.journal) {
		int aborted = vau_content_scope_abort(&writer);

		if (aborted)
			return aborted;
	}

	if (!rc)
		*out = writer.scope;
	return rc;
}
