/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_delete.h"
#include "format.h"
#include "native_ops.h"
#include "vita_agent.h"
#include <string.h>

static int hex(const char *s, unsigned n)
{
	if (!memchr(s, 0, n + 1) || strlen(s) != n)
		return 0;

	for (unsigned i = 0; i < n; i++)
		if (!strchr("0123456789abcdef", s[i]))
			return 0;
	return 1;
}

static int same(const struct vau_content_delete_request *a,
                const struct vau_content_delete_request *b)
{
	return vau_content_delete_target_same(a, b) && a->yes == b->yes &&
	       a->preview_sequence == b->preview_sequence;
}

int vau_content_delete_target_same(const struct vau_content_delete_request *a,
                                   const struct vau_content_delete_request *b)
{
	return a && b && !strcmp(a->subject, b->subject) && !strcmp(a->id, b->id) &&
	       !strcmp(a->title, b->title) && a->kind == b->kind && a->user == b->user &&
	       a->media_id == b->media_id;
}

int vau_content_delete_request_valid(const struct vau_content_delete_request *r)
{
	if (!r || r->kind > VAU_CONTENT_VIDEO || r->user >= 64 || r->preview_sequence > INT64_MAX ||
	    !hex(r->subject, 64) || !hex(r->id, 32) || !memchr(r->title, 0, sizeof(r->title)) ||
	    r->yes != 1) {
		return 0;
	}

	if (r->kind >= VAU_CONTENT_PHOTO)
		return !r->title[0] && !r->user && r->media_id && r->media_id <= INT64_MAX;
	return !r->media_id && (r->kind != VAU_CONTENT_APPLICATION || !r->user) &&
	       vau_title_valid(r->title) && strncmp(r->title, "NPXS", 4);
}

int vau_content_delete_record_valid(const struct vau_content_delete_record *r)
{
	if (!r || !vau_content_delete_request_valid(&r->request) || r->scope_sequence > INT64_MAX ||
	    r->state <= VAU_CONTENT_DELETE_IDLE || r->state > VAU_CONTENT_DELETE_UNCERTAIN ||
	    r->before.registered != 1 || r->before.application_present != 1 ||
	    r->after.registered > 1 || r->after.application_present > 1 || r->effect_started > 1 ||
	    r->after_known > 1 ||
	    (!r->after_known && (r->after.registered || r->after.application_present))) {
		return 0;
	}

	if (r->state == VAU_CONTENT_DELETE_APPROVAL && r->effect_started)
		return 0;
	if (r->state == VAU_CONTENT_DELETE_RUNNING && !r->effect_started)
		return 0;
	if (r->state != VAU_CONTENT_DELETE_COMPLETE)
		return 1;
	if (r->result || !r->effect_started || !r->after_known)
		return 0;
	if (r->request.kind >= VAU_CONTENT_PHOTO)
		return 0; /* Media completion needs its own observations. */
	if (r->request.kind == VAU_CONTENT_VITA_SAVEDATA)
		return r->scope_sequence && r->after.registered == 1 && r->after.application_present == 1;
	return !r->after.registered && !r->after.application_present;
}

static int adapter(const struct vau_content_delete_adapter *a)
{
	return a && a->clock && a->lookup && a->persist && a->inspect && a->allowed &&
	       a->approval_begin && a->approval_poll && a->approval_finish && a->native_start &&
	       a->native_poll;
}

static int active(const struct vau_content_delete *j)
{
	return j->record.state == VAU_CONTENT_DELETE_APPROVAL ||
	       j->record.state == VAU_CONTENT_DELETE_RUNNING;
}

void vau_content_delete_init(struct vau_content_delete *j)
{
	memset(j, 0, sizeof(*j));
}

static int save(struct vau_content_delete *j, const struct vau_content_delete_adapter *a)
{
	j->record.observed_us = a->clock(a->context);
	j->needs_persist      = 1;

	int rc = a->persist(a->context, &j->record);

	if (!rc)
		j->needs_persist = 0;
	return rc;
}

static int terminal(struct vau_content_delete *j, const struct vau_content_delete_adapter *a,
                    enum vau_content_delete_state state, int result)
{
	j->record.state  = state;
	j->record.result = result;
	return save(j, a);
}

int vau_content_delete_submit(struct vau_content_delete *j,
                              const struct vau_content_delete_adapter *a,
                              const struct vau_content_delete_request *r)
{
	if (!j || !adapter(a) || !vau_content_delete_request_valid(r))
		return VAU_INVALID;
	if (r->kind >= VAU_CONTENT_PHOTO)
		return VAU_UNSUPPORTED; /* Public worker integration pending. */
	if (r->kind == VAU_CONTENT_VITA_SAVEDATA && !a->savedata_complete)
		return VAU_UNSUPPORTED;
	if (!strcmp(j->record.request.id, r->id) && !strcmp(j->record.request.subject, r->subject))
		return same(&j->record.request, r) ? j->needs_persist ? VAU_BUSY : VAU_OK : VAU_STALE;
	if (active(j) || j->needs_persist)
		return VAU_BUSY;

	struct vau_content_delete_record stored = { 0 };
	int rc                                  = a->lookup(a->context, r->subject, r->id, &stored);

	if (rc < 0)
		return rc;
	if (!rc) {
		if (!vau_content_delete_record_valid(&stored) || !same(&stored.request, r))
			return VAU_STALE;

		vau_content_delete_init(j);
		j->record = stored;

		/* Never restart an uninstall after a reboot/response-loss ambiguity.
		 * A persisted pre-approval request needs a fresh physical decision. */
		if (stored.state == VAU_CONTENT_DELETE_RUNNING ||
		    stored.state == VAU_CONTENT_DELETE_APPROVAL) {
			return terminal(j, a,
			                stored.effect_started ? VAU_CONTENT_DELETE_UNCERTAIN
			                                      : VAU_CONTENT_DELETE_DENIED,
			                VAU_STALE);
		}

		return VAU_OK;
	}

	if (rc != 1)
		return VAU_DEVICE_ERROR;

	rc = a->allowed(a->context, r);
	if (rc)
		return rc;

	struct vau_content_observation before = { 0 };

	rc = a->inspect(a->context, r, &before);
	if (rc)
		return rc;
	if (before.registered != 1 || before.application_present != 1)
		return VAU_STALE;

	vau_content_delete_init(j);
	j->record.request = *r;
	j->record.before  = before;
	j->record.state   = VAU_CONTENT_DELETE_APPROVAL;
	rc                = save(j, a);
	if (rc)
		return rc;

	rc = a->approval_begin(a->context, r);
	return rc ? terminal(j, a, VAU_CONTENT_DELETE_FAILED, rc) : VAU_OK;
}

int vau_content_delete_poll(struct vau_content_delete *j,
                            const struct vau_content_delete_adapter *a)
{
	if (!j || !adapter(a))
		return VAU_INVALID;
	if (j->record.request.kind >= VAU_CONTENT_PHOTO)
		return VAU_UNSUPPORTED; /* Media worker integration pending. */
	if (j->needs_persist) {
		int rc = save(j, a);

		if (rc)
			return rc;

		/* A failed effect-intent flush must never turn into delayed execution. */
		if (j->record.state == VAU_CONTENT_DELETE_RUNNING)
			return terminal(j, a, VAU_CONTENT_DELETE_UNCERTAIN, VAU_STALE);
		if (j->record.state == VAU_CONTENT_DELETE_APPROVAL)
			return terminal(j, a, VAU_CONTENT_DELETE_DENIED, VAU_STALE);
		return VAU_OK;
	}

	if (j->record.state == VAU_CONTENT_DELETE_APPROVAL) {
		if (!j->decided) {
			int rc = a->approval_poll(a->context);

			if (rc == VAU_BUSY)
				return VAU_BUSY;

			j->decision = rc;
			j->decided  = 1;
		}

		int rc = a->approval_finish(a->context);

		if (rc)
			return rc;
		if (j->decision) {
			return terminal(j, a,
			                j->decision == VAU_DENIED ? VAU_CONTENT_DELETE_DENIED
			                                          : VAU_CONTENT_DELETE_FAILED,
			                j->decision);
		}

		rc = a->allowed(a->context, &j->record.request);
		if (rc)
			return terminal(j, a, VAU_CONTENT_DELETE_DENIED, rc);

		struct vau_content_observation now = { 0 };

		rc = a->inspect(a->context, &j->record.request, &now);
		if (rc || now.registered != 1 || now.application_present != 1)
			return terminal(j, a, VAU_CONTENT_DELETE_FAILED, rc ? rc : VAU_STALE);

		j->record.state          = VAU_CONTENT_DELETE_RUNNING;
		j->record.effect_started = 1;
		rc                       = save(j, a);
		if (rc)
			return rc;

		rc = a->native_start(a->context, &j->record.request);
		return rc ? terminal(j, a, VAU_CONTENT_DELETE_UNCERTAIN, rc) : VAU_BUSY;
	}

	if (j->record.state == VAU_CONTENT_DELETE_RUNNING) {
		int result = 0, rc = a->native_poll(a->context, &result);

		if (rc == VAU_BUSY)
			return rc;
		if (rc)
			return terminal(j, a, VAU_CONTENT_DELETE_UNCERTAIN, rc);

		j->record.result = result;
		rc               = a->inspect(a->context, &j->record.request, &j->record.after);
		if (rc)
			return terminal(j, a, VAU_CONTENT_DELETE_UNCERTAIN, rc);

		j->record.after_known = 1;
		if (result)
			return terminal(j, a, VAU_CONTENT_DELETE_FAILED, result);
		if (j->record.request.kind == VAU_CONTENT_VITA_SAVEDATA) {
			if (!a->savedata_complete)
				return terminal(j, a, VAU_CONTENT_DELETE_UNCERTAIN, VAU_UNSUPPORTED);
			if (j->record.after.registered != 1 || j->record.after.application_present != 1)
				return terminal(j, a, VAU_CONTENT_DELETE_UNCERTAIN, VAU_STALE);

			rc = a->savedata_complete(a->context, &j->record.request);
			if (rc)
				return terminal(j, a, VAU_CONTENT_DELETE_UNCERTAIN, rc);
		} else if (j->record.after.registered || j->record.after.application_present) {
			return terminal(j, a, VAU_CONTENT_DELETE_UNCERTAIN, VAU_STALE);
		}

		return terminal(j, a, VAU_CONTENT_DELETE_COMPLETE, 0);
	}

	return VAU_OK;
}

static int component(const char *p)
{
	if (!p)
		return 0;

	size_t n = 0;

	while (n < 256 && p[n])
		n++;
	if (!n || n == 256 || memchr(p, '/', n))
		return 0;

	char path[VAU_PATH_MAX], normalized[VAU_PATH_MAX];
	int written = vau_snprintf(path, sizeof(path), "ux0:cache/%s", p);

	return written > 0 && (size_t)written < sizeof(path) &&
	       !vau_path_normalize(path, normalized, sizeof(normalized)) && !strcmp(path, normalized);
}

static int emit(vau_content_path_visit visit, void *ctx, const char *prefix, const char *id,
                enum vau_content_path_role role)
{
	char path[VAU_PATH_MAX], normalized[VAU_PATH_MAX];
	int n = vau_snprintf(path, sizeof(path), "%s%s", prefix, id);

	if (n < 0 || (size_t)n >= sizeof(path) ||
	    vau_path_normalize(path, normalized, sizeof(normalized)) || strcmp(path, normalized)) {
		return VAU_INVALID;
	}

	return visit(ctx, path, role);
}

const char *vau_content_path_role_name(enum vau_content_path_role role)
{
	static const char *const names[] = {
		"application",
		"patch",
		"application_license",
		"savedata",
		"shared_savedata_expected_preserved",
		"add_on_content",
		"add_on_license",
		"cache",
		"application_metadata",
		"application_work",
		"book_content",
		"native_staging_cleanup",
		"game_data",
		"shared_game_data_expected_preserved",
		"media_database_expected_preserved",
		"media_database_journal",
		"media_file",
		"media_associated_file",
		"media_temporary_directory",
	};
	return (unsigned)role < sizeof(names) / sizeof(*names) ? names[role] : NULL;
}

int vau_content_plan_vita(const char *title, const struct vau_app_install_metadata *m, int shared,
                          vau_content_path_visit visit, void *ctx)
{
	if (!vau_title_valid(title) || !strncmp(title, "NPXS", 4) || !m || !visit ||
	    (shared != 0 && shared != 1) || !(m->present & 1) ||
	    (m->present & ~((1u << VAU_APP_INSTALL_FIELDS) - 1))) {
		return VAU_INVALID;
	}

	/* The native finalizer's fixed title list can trigger umass cleanup and
	 * VideoExport on empr0:. Their complete native scope needs a separate
	 * planner; do not present the ordinary application's roots as complete. */
	if (!strcmp(title, "PCSC00025") || !strcmp(title, "PCSC80003") || !strcmp(title, "PCSC00046"))
		return VAU_UNSUPPORTED;

	char expected[VAU_PATH_MAX];
	int n = vau_snprintf(expected, sizeof(expected), "ux0:app/%s", title);

	if (n < 0 || (size_t)n >= sizeof(expected) || !memchr(m->values[0], 0, sizeof(m->values[0])) ||
	    strcmp(expected, m->values[0])) {
		return VAU_UNSUPPORTED;
	}

	/* Validate the entire metadata snapshot before giving any path to a
	 * visitor. Directory IDs cannot inject a different mount or parent path. */
	for (unsigned i = 1; i < VAU_APP_INSTALL_FIELDS; i++) {
		if (!(m->present & (1u << i)))
			continue;
		if (!memchr(m->values[i], 0, sizeof(m->values[i])) ||
		    (m->values[i][0] && !component(m->values[i]))) {
			return VAU_INVALID;
		}
	}

	int rc;
#define PATH(prefix, id, role)                   \
	do {                                         \
		rc = emit(visit, ctx, prefix, id, role); \
		if (rc)                                  \
			return rc;                           \
	} while (0)
	PATH("ux0:app/", title, VAU_CONTENT_ORIGIN);
	PATH("ux0:patch/", title, VAU_CONTENT_PATCH);
	PATH("ux0:license/app/", title, VAU_CONTENT_LICENSE);
	if ((m->present & 2) && m->values[1][0]) {
		for (unsigned user = 0; user < 64; user++) {
			char prefix[48];

			vau_snprintf(prefix, sizeof(prefix), "ux0:user/%02u/savedata/", user);
			PATH(prefix, m->values[1], shared ? VAU_CONTENT_SHARED_SAVEDATA : VAU_CONTENT_SAVEDATA);
		}
	}

	for (unsigned i = 3; i < VAU_APP_INSTALL_FIELDS; i++) {
		if ((m->present & (1u << i)) && m->values[i][0]) {
			PATH("ux0:addcont/", m->values[i], VAU_CONTENT_ADDCONT);
			PATH("ux0:license/addcont/", m->values[i], VAU_CONTENT_ADDCONT_LICENSE);
		}
	}

	if ((m->present & 4) && m->values[2][0])
		PATH("ux0:cache/", m->values[2], VAU_CONTENT_CACHE);
	PATH("ux0:appmeta/", title, VAU_CONTENT_APPMETA);
	PATH("ur0:appmeta/", title, VAU_CONTENT_APPMETA);
	PATH("ux0:temp/app_work/", title, VAU_CONTENT_WORK);
	if (!strcmp(title, "PCSC80012"))
		PATH("ux0:book", "", VAU_CONTENT_BOOK);
	/* The SDK cleans whole shared staging directories before/after moving
	 * this title's data. Existing leftovers must also pass recursive preflight. */
	PATH("ux0:temp/game", "", VAU_CONTENT_STAGING);
	PATH("ur0:temp/game", "", VAU_CONTENT_STAGING);
#undef PATH
	return VAU_OK;
}

int vau_content_plan_legacy(const char *title, const struct vau_legacy_install_metadata *m,
                            int shared, vau_content_path_visit visit, void *ctx)
{
	static const char prefix[] = "ux0:pspemu/PSP/GAME/";

	if (!vau_title_valid(title) || !strncmp(title, "NPXS", 4) || !m || !visit ||
	    (shared != 0 && shared != 1) || !memchr(m->origin, 0, sizeof(m->origin)) ||
	    !memchr(m->gamedata_id, 0, sizeof(m->gamedata_id))) {
		return VAU_INVALID;
	}

	char normalized[VAU_PATH_MAX], gamedata[VAU_PATH_MAX] = { 0 };
	size_t length = strlen(m->origin), prefix_bytes = sizeof(prefix) - 1;

	if (length <= prefix_bytes || strncmp(m->origin, prefix, prefix_bytes) ||
	    vau_path_normalize(m->origin, normalized, sizeof(normalized)) ||
	    strcmp(m->origin, normalized)) {
		return VAU_INVALID;
	}

	int same = 0;

	if (m->gamedata_id[0]) {
		if (!component(m->gamedata_id))
			return VAU_INVALID;

		int n = vau_snprintf(gamedata, sizeof(gamedata), "%s%s", prefix, m->gamedata_id);

		if (n < 0 || (size_t)n >= sizeof(gamedata))
			return VAU_INVALID;

		same = !strcmp(gamedata, m->origin);

		/* Overlapping roots need merged descendant roles in the capture
		 * adapter. Do not emit an ambiguous duplicate subtree for now. */
		size_t bytes = strlen(gamedata);

		if (!same && ((!strncmp(m->origin, gamedata, bytes) && m->origin[bytes] == '/') ||
		              (!strncmp(gamedata, m->origin, length) && gamedata[length] == '/'))) {
			return VAU_UNSUPPORTED;
		}
	}

	int rc = emit(visit, ctx, m->origin, "", VAU_CONTENT_ORIGIN);

	if (rc)
		return rc;

	/* The native backend stages the origin independently of the sharing
	 * predicate; an identical GAMEDATA_ID is not a second preserved root. */
	if (gamedata[0] && !same) {
		rc = emit(visit, ctx, gamedata, "",
		          shared ? VAU_CONTENT_SHARED_GAMEDATA : VAU_CONTENT_GAMEDATA);
		if (rc)
			return rc;
	}

	rc = emit(visit, ctx, "ur0:appmeta/", title, VAU_CONTENT_APPMETA);
	if (rc)
		return rc;

	rc = emit(visit, ctx, "ux0:pspemu/temp/game", "", VAU_CONTENT_STAGING);
	if (rc)
		return rc;
	return emit(visit, ctx, "ur0:temp/game", "", VAU_CONTENT_STAGING);
}

int vau_content_plan_application(const char *title, const struct vau_app_install_metadata *m,
                                 int shared, vau_content_path_visit visit, void *ctx)
{
	if (!m || !(m->present & 1) || (m->present & ~((1u << VAU_APP_INSTALL_FIELDS) - 1)) ||
	    !memchr(m->values[0], 0, sizeof(m->values[0]))) {
		return VAU_INVALID;
	}

	if (!strncmp(m->values[0], "ux0:pspemu/PSP/GAME/", 20)) {
		struct vau_legacy_install_metadata legacy;

		memcpy(legacy.origin, m->values[0], sizeof(legacy.origin));
		memcpy(legacy.gamedata_id, m->gamedata_id, sizeof(legacy.gamedata_id));
		return vau_content_plan_legacy(title, &legacy, shared, visit, ctx);
	}

	return vau_content_plan_vita(title, m, shared, visit, ctx);
}

int vau_content_savedata_backup_eligible(const char *id)
{
	if (!id)
		return 0;

	for (unsigned i = 0; i < 9; i++)
		if (i < 4 ? (id[i] < 'A' || id[i] > 'Z') : (id[i] < '0' || id[i] > '9'))
			return 0;
	return id[9] == 0;
}

int vau_content_savedata_id_valid(const char *id)
{
	return component(id);
}

int vau_content_savedata_backup_match(const char *id, const char *name, size_t bytes, int regular)
{
	if (!vau_content_savedata_backup_eligible(id) || !name || (regular != 0 && regular != 1))
		return VAU_INVALID;

	/* The directory reader supplies the bounded name length. No read beyond
	 * that span is needed, including for filtered oversized filenames. */
	if (!regular || bytes != 31)
		return 0;
	return !memchr(name, 0, bytes) && !memcmp(name, id, 9);
}

int vau_content_plan_savedata(const char *title, const struct vau_app_install_metadata *m,
                              unsigned user, const char *backup, vau_content_path_visit visit,
                              void *ctx)
{
	if (!vau_title_valid(title) || !strncmp(title, "NPXS", 4) || !m || !visit || user >= 64 ||
	    !backup || (m->present & 3) != 3 || (m->present & ~((1u << VAU_APP_INSTALL_FIELDS) - 1)) ||
	    !memchr(m->values[0], 0, sizeof(m->values[0])) ||
	    !vau_content_savedata_id_valid(m->values[1])) {
		return VAU_INVALID;
	}

	size_t backup_bytes = 0;

	while (backup_bytes < 32 && backup[backup_bytes])
		backup_bytes++;
	if (backup_bytes == 32)
		return VAU_INVALID;

	char expected[VAU_PATH_MAX], prefix[64], normalized[VAU_PATH_MAX];
	int n = vau_snprintf(expected, sizeof(expected), "ux0:app/%s", title);

	if (n < 0 || (size_t)n >= sizeof(expected))
		return VAU_INVALID;

	/* Cartridge mode ignores the requested numbered user; this planner only
	 * describes the writable Vita backend whose selector was verified. */
	if (strcmp(expected, m->values[0]))
		return VAU_UNSUPPORTED;
	if (backup[0]) {
		if (vau_content_savedata_backup_match(m->values[1], backup, backup_bytes, 1) != 1)
			return VAU_INVALID;

		n = vau_snprintf(expected, sizeof(expected), "ux0:user/%02u/savedata_backup/%s", user,
		                 backup);
		if (n < 0 || (size_t)n >= sizeof(expected) || strchr(backup, '/') ||
		    vau_path_normalize(expected, normalized, sizeof(normalized)) ||
		    strcmp(expected, normalized)) {
			return VAU_INVALID;
		}
	}

	/* Validate the entire selection before publishing any potential effect. */
	vau_snprintf(prefix, sizeof(prefix), "ux0:user/%02u/savedata/", user);

	int rc = emit(visit, ctx, prefix, m->values[1], VAU_CONTENT_SAVEDATA);

	if (rc)
		return rc;
	if (backup[0]) {
		vau_snprintf(prefix, sizeof(prefix), "ux0:user/%02u/savedata_backup/", user);
		rc = emit(visit, ctx, prefix, backup, VAU_CONTENT_SAVEDATA);
		if (rc)
			return rc;

		vau_snprintf(prefix, sizeof(prefix), "ux0:user/%02u/savedata_backup/_", user);
		rc = emit(visit, ctx, prefix, backup, VAU_CONTENT_STAGING);
		if (rc)
			return rc;
	}

	return emit(visit, ctx, "ux0:temp/game", "", VAU_CONTENT_STAGING);
}

struct preflight {
	const struct vau_file_policy *policy;
	const char *subject;
	const struct vau_content_preflight_adapter *adapter;
	char root[VAU_PATH_MAX];
};

static int lower(int c)
{
	return c >= 'A' && c <= 'Z' ? c + 'a' - 'A' : c;
}

static int child(const char *p, const char *root)
{
	while (*root && *p && lower(*p) == lower(*root)) {
		p++;
		root++;
	}

	return !*root && (!*p || *p == '/');
}

static int descendant(void *ctx, const char *path)
{
	struct preflight *p = ctx;
	char normalized[VAU_PATH_MAX];

	if (vau_path_normalize(path, normalized, sizeof(normalized)) || strcmp(path, normalized) ||
	    !child(path, p->root)) {
		return VAU_INVALID;
	}

	if (p->adapter->stopped(p->adapter->context))
		return VAU_DENIED;
	return vau_policy_evaluate(p->policy, p->subject, VAU_FS_PURGE, path, 1) == VAU_POLICY_ALLOW
	               ? VAU_OK
	               : VAU_DENIED;
}

static int root(void *ctx, const char *path, enum vau_content_path_role role)
{
	struct preflight *p = ctx;

	if (p->adapter->stopped(p->adapter->context))
		return VAU_DENIED;

	(void)role;

	/* The native sharing query returns "unshared" on database failure. A
	 * planned preservation therefore cannot exempt a path from write policy
	 * or a complete recursive check before invoking that SDK operation. */
	strcpy(p->root, path);

	/* Evaluate potential roots as well: native staging can be created even
	 * when initially absent. No broad ACL or physical OK overrides hard bans. */
	int rc = descendant(p, path);

	if (rc)
		return rc;
	return p->adapter->walk(p->adapter->context, path, descendant, p);
}

int vau_content_preflight_vita(const struct vau_file_policy *policy, const char *subject, int yes,
                               const char *title, const struct vau_app_install_metadata *metadata,
                               int shared, const struct vau_content_preflight_adapter *a)
{
	if (!policy || !subject || strlen(subject) != 64 || !a || !a->walk || !a->stopped ||
	    vau_policy_validate(policy)) {
		return VAU_INVALID;
	}

	if (yes != 1)
		return VAU_DENIED;

	struct preflight p = { .policy = policy, .subject = subject, .adapter = a };

	return vau_content_plan_application(title, metadata, shared, root, &p);
}

int vau_content_target_json(const struct vau_content_delete_request *r, char *out, size_t cap)
{
	if (!out || !cap)
		return VAU_INVALID;

	out[0] = 0;
	if (!vau_content_delete_request_valid(r))
		return VAU_INVALID;
	if (r->kind == VAU_CONTENT_APPLICATION)
		return 0;

	int n;

	if (r->kind >= VAU_CONTENT_PHOTO) {
		static const char *const kinds[] = { "photo", "music", "video" };
		n = vau_snprintf(out, cap, ",\"kind\":\"%s\",\"media_id\":\"%llu\"",
		                 kinds[r->kind - VAU_CONTENT_PHOTO], (unsigned long long)r->media_id);
	} else {
		n = vau_snprintf(out, cap, ",\"kind\":\"vita_savedata\",\"user\":%u", r->user);
	}

	if (n < 0 || (size_t)n >= cap) {
		out[0] = 0;
		return VAU_UNSUPPORTED;
	}

	return n;
}

int vau_content_record_json(const struct vau_content_delete_record *r, int persisted, char *out,
                            size_t cap)
{
	if (!out || !cap)
		return VAU_INVALID;

	out[0] = 0;
	if (!vau_content_delete_record_valid(r) || (persisted != 0 && persisted != 1))
		return VAU_INVALID;

	char target[64];
	int target_size = vau_content_target_json(&r->request, target, sizeof(target));

	if (target_size < 0)
		return target_size;

	static const char *const states[] = {
		"idle", "approval_pending", "running", "complete", "denied", "failed", "uncertain",
	};

	const int media         = r->request.kind >= VAU_CONTENT_PHOTO;
	const char *present_key = media ? "file_present" : "application_present";
	char title[16]          = "null";

	if (!media)
		vau_snprintf(title, sizeof(title), "\"%s\"", r->request.title);

	char after[96] = "null";

	if (r->after_known) {
		vau_snprintf(after, sizeof(after), "{\"registered\":%s,\"%s\":%s}",
		             r->after.registered ? "true" : "false", present_key,
		             r->after.application_present ? "true" : "false");
	}

	int n = vau_snprintf(
	        out, cap,
	        "{\"subject\":\"%s\",\"operation_id\":\"%s\",\"title_id\":%s%s,\"state\":\"%s\","
	        "\"effect_started\":%s,\"native_result\":%d,\"persisted\":%s,\"observed_us\":\"%llu\","
	        "\"scope_sequence\":\"%llu\",\"preview_scope\":\"%llu\",\"%s\":{\"before\":{"
	        "\"registered\":true,"
	        "\"%s\":true},\"after\":%s}}",
	        r->request.subject, r->request.id, title, target, states[r->state],
	        r->effect_started ? "true" : "false", r->result, persisted ? "true" : "false",
	        (unsigned long long)r->observed_us, (unsigned long long)r->scope_sequence,
	        (unsigned long long)r->request.preview_sequence, media ? "media" : "registration",
	        present_key, after);

	if (n < 0 || (size_t)n >= cap) {
		out[0] = 0;
		return VAU_UNSUPPORTED;
	}

	return n;
}
