/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "file_mutations.h"
#include "file_tree.h"
#include "format.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <string.h>

#define VAU_IO_ENOENT ((int)0x80010002u)

static int same_mount(const char *a, const char *b)
{
	const char *x = strchr(a, ':'), *y = strchr(b, ':');

	return x && y && x - a == y - b && !memcmp(a, b, (size_t)(x - a));
}

/* Trashing is a same-mount rename to <mount>:data/vita-agent-use/trash/<subject>_<id>;
 * that operation id is what a later purge names as its trash id. */
int vau_mutation_trash_path(const struct vau_write_request *r, char out[VAU_PATH_MAX])
{
	char stage[VAU_PATH_MAX];
	int rc = vau_upload_stage_path(r, stage);

	if (rc)
		return rc;

	char mount[9]     = { 0 };
	const char *colon = strchr(stage, ':');

	memcpy(mount, stage, (size_t)(colon - stage));

	int n = vau_snprintf(out, VAU_PATH_MAX, "%s:data/vita-agent-use/trash/%s_%s", mount, r->subject,
	                     r->id);

	return n > 0 && n < (int)VAU_PATH_MAX ? VAU_OK : VAU_INVALID;
}

static int progress(struct vau_upload_context *c, const struct vau_write_request *r,
                    const char *step, unsigned started)
{
	struct vau_write_record event = { .request        = *r,
		                              .phase          = VAU_WRITE_PROGRESS,
		                              .result         = VAU_BUSY,
		                              .effect_started = started,
		                              .observed_us    = c->clock(c->context) };
	strcpy(event.detail, step);
	return vau_journal_append(c->journal, &event);
}

static int lookup(void *opaque, const char *subject, const char *id, struct vau_write_record *out)
{
	struct vau_upload_context *c = opaque;

	return vau_journal_lookup(c->journal, subject, id, out);
}

static int audit(void *opaque, struct vau_write_record *out)
{
	struct vau_upload_context *c = opaque;

	out->observed_us = c->clock(c->context);
	if (out->phase == VAU_WRITE_INTENT) {
		int rc = vau_write_observe(out->request.path, &out->before);

		if (rc)
			return rc;
		if (out->request.operation == VAU_FS_TRASH) {
			rc = vau_mutation_trash_path(&out->request, out->effect_path);
		} else {
			strcpy(out->effect_path, out->request.operation == VAU_FS_RENAME_SOURCE
			                                 ? out->request.destination
			                                 : out->request.path);
		}

		if (rc)
			return rc;
		if (out->request.operation != VAU_FS_MKDIR) {
			rc = vau_write_observe(out->effect_path, &out->destination_before);
			if (rc)
				return rc;
		}
	} else if (out->phase == VAU_WRITE_COMPLETE) {
		(void)vau_write_observe(out->request.path, &out->after);
		if (out->request.operation != VAU_FS_MKDIR)
			(void)vau_write_observe(out->effect_path, &out->destination_after);
		if (!out->result && (out->request.operation == VAU_FS_MKDIR
		                             ? out->after.state != VAU_STATE_DIRECTORY
		                             : out->after.state != VAU_STATE_MISSING ||
		                                       out->destination_after.state != out->before.state)) {
			out->phase  = VAU_WRITE_INTENT;
			out->result = VAU_RECOVERY_REQUIRED;
			return VAU_RECOVERY_REQUIRED;
		}
	}

	return vau_journal_append(c->journal, out);
}

static int stop(void *opaque)
{
	struct vau_upload_context *c = opaque;

	return c->stopped(c->context);
}

struct visit_context {
	vau_write_visit visit;
	void *context;
};

static int visit(void *opaque, const char *path, const struct vau_file_info *info)
{
	(void)info;

	struct visit_context *v = opaque;

	return v->visit(v->context, path);
}

static int parent(const char *path)
{
	char p[VAU_PATH_MAX];

	strcpy(p, path);

	char *slash = strrchr(p, '/');

	if (slash) {
		*slash = 0;
	} else {
		char *colon = strchr(p, ':');

		colon[1] = 0;
	}

	struct vau_file_info info;
	int rc = vau_vita_file_stat(NULL, p, &info);

	return rc ? rc : info.kind == VAU_FILE_DIRECTORY ? VAU_OK : VAU_INVALID;
}

static int missing(const char *path)
{
	struct vau_file_info info;
	int rc = vau_vita_file_stat(NULL, path, &info);

	return rc == VAU_IO_ENOENT ? VAU_OK : rc < 0 ? rc : VAU_STALE;
}

static int preflight(void *opaque, const struct vau_write_request *r, vau_write_visit visitor,
                     void *visit_context)
{
	struct vau_upload_context *c = opaque;

	if (r->operation == VAU_FS_MKDIR) {
		if (r->recursive)
			return VAU_UNSUPPORTED;

		int rc = missing(r->path);

		return rc ? rc : parent(r->path);
	}

	if (r->operation != VAU_FS_RENAME_SOURCE && r->operation != VAU_FS_TRASH)
		return VAU_UNSUPPORTED;

	struct visit_context v = { visitor, visit_context };
	int rc                 = vau_native_tree_walk(r->path, 0, visit, &v, c->stopped, c->context);

	if (rc)
		return rc;

	char trash[VAU_PATH_MAX];
	const char *destination = r->destination;

	if (r->operation == VAU_FS_TRASH) {
		rc = vau_mutation_trash_path(r, trash);
		if (rc)
			return rc;

		destination = trash;
	}

	if (!same_mount(r->path, destination))
		return VAU_UNSUPPORTED; /* Cross-mount copy backend still required. */
	if (r->operation == VAU_FS_RENAME_SOURCE) {
		rc = parent(destination);
		if (rc)
			return rc;
	}

	return missing(destination);
}

static int trash_parents(struct vau_upload_context *c, const struct vau_write_request *r,
                         const char *target, unsigned *started)
{
	char path[VAU_PATH_MAX];

	strcpy(path, target);
	for (size_t i = 0; path[i]; ++i) {
		if (path[i] == '/') {
			path[i] = 0;

			struct vau_file_info info;
			int rc = vau_vita_file_stat(NULL, path, &info);

			if (rc == VAU_IO_ENOENT) {
				rc = progress(c, r, "trash_mkdir_intent", 0);
				if (!rc && c->stopped(c->context))
					rc = VAU_DENIED;
				if (!rc) {
					*started = 1;
					rc       = sceIoMkdir(path, 0777);
				}

				if (!rc)
					rc = progress(c, r, "trash_mkdir", 1);
				if (!rc)
					rc = vau_vita_file_stat(NULL, path, &info);
			}

			path[i] = '/';
			if (rc)
				return rc;
			if (info.kind != VAU_FILE_DIRECTORY)
				return VAU_DENIED;
		}
	}

	return VAU_OK;
}

static int sync_mount(const char *path)
{
	char mount[9]     = { 0 };
	const char *colon = strchr(path, ':');

	memcpy(mount, path, (size_t)(colon - path) + 1);

	int rc = sceIoSync(mount, 0);

	return rc < 0 ? rc : VAU_OK;
}

struct recheck_context {
	struct vau_upload_context *c;
	const struct vau_write_request *r;
};

/* Policy again for every descendant just before the rename, as preflight may be
 * stale; for a move, each child is also checked at the path it will land on. */
static int recheck(void *opaque, const char *path, const struct vau_file_info *info)
{
	(void)info;

	const struct recheck_context *v = opaque;

	if (vau_policy_evaluate(v->c->policy, v->r->subject, v->r->operation, path, (int)v->r->yes) !=
	    VAU_POLICY_ALLOW) {
		return VAU_DENIED;
	}

	if (v->r->operation == VAU_FS_RENAME_SOURCE) {
		char destination[VAU_PATH_MAX];
		size_t prefix = strlen(v->r->destination), tail = strlen(path) - strlen(v->r->path);

		if (prefix + tail >= sizeof(destination))
			return VAU_INVALID;

		memcpy(destination, v->r->destination, prefix);
		memcpy(destination + prefix, path + strlen(v->r->path), tail + 1);
		if (vau_policy_evaluate(v->c->policy, v->r->subject, VAU_FS_RENAME_DESTINATION, destination,
		                        (int)v->r->yes) != VAU_POLICY_ALLOW) {
			return VAU_DENIED;
		}
	}

	return VAU_OK;
}

/* Same journaled intent/done protocol as apply() in upload_commit.c. */
static int apply(void *opaque, const struct vau_write_request *r, unsigned *started,
                 unsigned *readback)
{
	struct vau_upload_context *c = opaque;

	*started  = 0;
	*readback = 0;

	int rc;

	if (r->operation == VAU_FS_MKDIR) {
		rc = progress(c, r, "mkdir_intent", 0);
		if (rc)
			return rc;
		if (c->stopped(c->context))
			return VAU_DENIED;

		rc       = sceIoMkdir(r->path, 0777);
		*started = 1;
		if (rc < 0)
			return VAU_RECOVERY_REQUIRED;
	} else {
		struct recheck_context v = { c, r };

		rc = vau_native_tree_walk(r->path, 0, recheck, &v, c->stopped, c->context);
		if (rc)
			return rc;

		char trash[VAU_PATH_MAX];
		const char *destination = r->destination;

		if (r->operation == VAU_FS_TRASH) {
			rc = vau_mutation_trash_path(r, trash);
			if (rc)
				return rc;

			rc = trash_parents(c, r, trash, started);
			if (rc)
				return *started ? VAU_RECOVERY_REQUIRED : rc;

			destination = trash;
		}

		rc = missing(destination);
		if (rc)
			return *started ? VAU_RECOVERY_REQUIRED : rc;

		rc = progress(c, r, r->operation == VAU_FS_TRASH ? "trash_intent" : "rename_intent",
		              *started);
		if (rc)
			return *started ? VAU_RECOVERY_REQUIRED : rc;
		if (c->stopped(c->context))
			return *started ? VAU_RECOVERY_REQUIRED : VAU_DENIED;

		rc       = sceIoRename(r->path, destination);
		*started = 1;
		if (rc < 0)
			return VAU_RECOVERY_REQUIRED;
	}

	rc = sync_mount(r->path);
	if (rc)
		return VAU_RECOVERY_REQUIRED;

	rc = progress(c, r,
	              r->operation == VAU_FS_MKDIR   ? "mkdir_done"
	              : r->operation == VAU_FS_TRASH ? "trash_done"
	                                             : "rename_done",
	              1);
	return rc ? VAU_RECOVERY_REQUIRED : VAU_OK;
}

int vau_mutation_execute(struct vau_upload_context *c, const struct vau_write_request *r,
                         struct vau_write_record *out)
{
	if (!c || !c->policy || !c->journal || !c->clock || !c->stopped)
		return VAU_INVALID;
	if (r && r->operation == VAU_FS_PURGE)
		return vau_trash_purge(c, r, out);

	struct vau_write_adapter adapter = { .context   = c,
		                                 .lookup    = lookup,
		                                 .audit     = audit,
		                                 .preflight = preflight,
		                                 .apply     = apply,
		                                 .stopped   = stop };
	return vau_write_execute(c->policy, &adapter, r, out);
}
