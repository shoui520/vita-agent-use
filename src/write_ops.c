/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "write_ops.h"
#include <string.h>

static int lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c + 'a' - 'A' : c;
}

static int same(const char *a, const char *b)
{
	while (*a && *b && lower(*a) == lower(*b)) {
		++a;
		++b;
	}

	return !*a && !*b;
}

static int child(const char *p, const char *root)
{
	while (*p && *root && lower(*p) == lower(*root)) {
		++p;
		++root;
	}

	return !*root && (!*p || *p == '/');
}

static int config_path(const char *p)
{
	return same(p, "ur0:tai/config.txt") || same(p, "ux0:tai/config.txt") ||
	       same(p, "uma0:tai/config.txt");
}

static int valid_id(const char *p)
{
	for (unsigned i = 0; i < 32; ++i)
		if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f')))
			return 0;
	return !p[32];
}

static int digest(const char *p)
{
	for (unsigned i = 0; i < 64; ++i)
		if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f')))
			return 0;
	return !p[64];
}

int vau_write_request_same(const struct vau_write_request *a, const struct vau_write_request *b)
{
	return !strcmp(a->id, b->id) && !strcmp(a->subject, b->subject) && same(a->path, b->path) &&
	       same(a->destination, b->destination) && a->operation == b->operation &&
	       a->yes == b->yes && a->recursive == b->recursive && a->overwrite == b->overwrite &&
	       a->bytes == b->bytes && !strcmp(a->sha256, b->sha256) &&
	       !strcmp(a->expected_sha256, b->expected_sha256) && !strcmp(a->trash_id, b->trash_id);
}

struct preflight {
	const struct vau_file_policy *policy;
	const struct vau_write_adapter *adapter;
	const struct vau_write_request *request;
};

static int visit(void *context, const char *path)
{
	struct preflight *p = context;

	const struct vau_write_request *r = p->request;
	char normalized[VAU_PATH_MAX];

	if (vau_path_normalize(path, normalized, sizeof(normalized)) || !child(normalized, r->path))
		return VAU_INVALID;
	if (p->adapter->stopped(p->adapter->context))
		return VAU_DENIED;
	if (vau_policy_evaluate(p->policy, r->subject, r->operation, normalized, (int)r->yes) !=
	    VAU_POLICY_ALLOW) {
		return VAU_DENIED;
	}

	if (r->operation == VAU_FS_RENAME_SOURCE) {
		char destination[VAU_PATH_MAX];
		size_t prefix = strlen(r->destination), tail = strlen(normalized) - strlen(r->path);

		if (prefix + tail >= sizeof(destination))
			return VAU_INVALID;

		memcpy(destination, r->destination, prefix);
		memcpy(destination + prefix, normalized + strlen(r->path), tail + 1);
		if (vau_policy_evaluate(p->policy, r->subject, VAU_FS_RENAME_DESTINATION, destination,
		                        (int)r->yes) != VAU_POLICY_ALLOW ||
		    config_path(destination)) {
			return VAU_DENIED;
		}
	}

	return VAU_OK;
}

int vau_write_execute(const struct vau_file_policy *policy, const struct vau_write_adapter *a,
                      const struct vau_write_request *request, struct vau_write_record *out)
{
	if (!out)
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	if (!a || !request || !a->lookup || !a->audit || !a->preflight || !a->apply || !a->stopped ||
	    !memchr(request->id, 0, sizeof(request->id)) || !valid_id(request->id) ||
	    !memchr(request->subject, 0, sizeof(request->subject)) ||
	    !memchr(request->path, 0, sizeof(request->path)) ||
	    !memchr(request->destination, 0, sizeof(request->destination)) ||
	    !memchr(request->sha256, 0, sizeof(request->sha256)) ||
	    !memchr(request->expected_sha256, 0, sizeof(request->expected_sha256)) ||
	    !memchr(request->trash_id, 0, sizeof(request->trash_id)) || request->yes > 1 ||
	    request->recursive > 1 || request->overwrite > 1 || request->operation == VAU_FS_READ ||
	    request->operation == VAU_FS_RENAME_DESTINATION ||
	    (unsigned)request->operation > VAU_FS_PURGE) {
		return VAU_INVALID;
	}

	if (request->operation == VAU_FS_PURGE
	            ? !valid_id(request->trash_id) || !strcmp(request->trash_id, request->id)
	            : !!*request->trash_id) {
		return VAU_INVALID;
	}

	if (request->operation == VAU_FS_WRITE) {
		if (request->recursive || request->bytes > INT64_MAX || !digest(request->sha256) ||
		    (request->overwrite ? (*request->expected_sha256 && !digest(request->expected_sha256))
		                        : !!*request->expected_sha256)) {
			return VAU_INVALID;
		}
	} else if (request->overwrite || request->bytes || *request->sha256 ||
	           *request->expected_sha256) {
		return VAU_INVALID;
	}

	if (request->operation == VAU_FS_WRITE && request->overwrite && !request->yes)
		return VAU_DENIED;

	struct vau_write_request r = *request;

	if (vau_path_normalize(request->path, r.path, sizeof(r.path)))
		return VAU_INVALID;
	if (r.operation == VAU_FS_RENAME_SOURCE) {
		if (vau_path_normalize(request->destination, r.destination, sizeof(r.destination)) ||
		    child(r.destination, r.path) || child(r.path, r.destination)) {
			return VAU_INVALID;
		}

		if (vau_policy_evaluate(policy, r.subject, VAU_FS_RENAME_DESTINATION, r.destination,
		                        (int)r.yes) != VAU_POLICY_ALLOW ||
		    config_path(r.destination)) {
			return VAU_DENIED;
		}
	} else if (*r.destination) {
		return VAU_INVALID;
	}

	if (vau_policy_evaluate(policy, r.subject, r.operation, r.path, (int)r.yes) != VAU_POLICY_ALLOW)
		return VAU_DENIED;
	if (a->stopped(a->context))
		return VAU_DENIED;

	int rc = a->lookup(a->context, r.subject, r.id, out);

	if (rc == 0) {
		if (!vau_write_request_same(&r, &out->request))
			return VAU_STALE;

		/* An intent without completion is UNKNOWN, never automatically rerun.
		 * Native recovery must reconcile it before the peer retries. */
		return out->phase == VAU_WRITE_COMPLETE ? out->result : VAU_BUSY;
	}

	if (rc != 1)
		return rc < 0 ? rc : VAU_DEVICE_ERROR;

	memset(out, 0, sizeof(*out));
	out->request = r;

	struct preflight p = { policy, a, &r };

	rc = visit(&p, r.path);
	if (rc < 0)
		return rc;

	rc = a->preflight(a->context, &r, visit, &p);
	if (rc < 0)
		return rc;
	if (config_path(r.path)) {
		if (!a->config_check)
			return VAU_DENIED;

		rc = a->config_check(a->context, &r);
		if (rc < 0)
			return rc;

		out->readback_required = 1;
	}

	if (a->stopped(a->context))
		return VAU_DENIED;

	out->phase  = VAU_WRITE_INTENT;
	out->result = VAU_BUSY;
	rc          = a->audit(a->context, out);
	if (rc < 0)
		return rc;
	if (a->stopped(a->context))
		out->result = VAU_DENIED;
	else
		out->result = a->apply(a->context, &r, &out->effect_started, &out->readback_required);
	if (config_path(r.path))
		out->readback_required = 1;
	if (out->result == VAU_RECOVERY_REQUIRED)
		return VAU_RECOVERY_REQUIRED;

	out->phase = VAU_WRITE_COMPLETE;
	rc         = a->audit(a->context, out);

	/* If completion persistence fails, report failure with truthful effect
	 * flags. Durable intent forces reconciliation rather than blind replay. */
	return rc < 0 ? rc : out->result;
}
