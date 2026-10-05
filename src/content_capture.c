/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "content_capture.h"
#include "file_tree.h"
#include "format.h"
#include "native_ops.h"
#include <string.h>

struct capture {
	struct vau_content_scope_writer *writer;
	const struct vau_content_capture_adapter *adapter;
	const struct vau_file_policy *policy;
	char root[VAU_PATH_MAX];
	enum vau_content_path_role role;
};

static int capture_failed(struct capture *c, int rc)
{
	if (rc && !c->writer->failure)
		c->writer->failure = rc;
	return rc;
}

static int capture_check(struct capture *c, const char *path)
{
	char normalized[VAU_PATH_MAX];
	size_t n = strlen(c->root);

	if (vau_path_normalize(path, normalized, sizeof(normalized)) || strcmp(path, normalized) ||
	    strncmp(path, c->root, n) || (path[n] && path[n] != '/')) {
		return VAU_INVALID;
	}

	if (c->policy) {
		if (c->adapter->stopped(c->adapter->context))
			return VAU_DENIED;
		if (c->role == VAU_CONTENT_MEDIA_TEMP &&
		    vau_policy_evaluate(c->policy, c->writer->scope.request.subject, VAU_FS_WRITE, path,
		                        1) != VAU_POLICY_ALLOW) {
			return VAU_DENIED;
		}

		if (vau_policy_evaluate(c->policy, c->writer->scope.request.subject, VAU_FS_PURGE, path,
		                        1) != VAU_POLICY_ALLOW) {
			return VAU_DENIED;
		}
	}

	return 0;
}

static int capture_observation_check(struct capture *c,
                                     const struct vau_content_path_observation *o)
{
	if (!vau_content_path_observation_valid(o))
		return VAU_INVALID;
	if (c->policy && o->state == VAU_STATE_UNKNOWN)
		return o->error;
	if (c->policy && o->state == VAU_STATE_OTHER)
		return VAU_DENIED;
	return 0;
}

static int capture_visit(void *ctx, const char *path, const struct vau_content_path_observation *o)
{
	struct capture *c = ctx;
	int rc            = capture_check(c, path);

	if (!rc)
		rc = capture_observation_check(c, o);
	if (!rc)
		rc = vau_content_scope_add(c->writer, path, c->role, 0, o);
	return capture_failed(c, rc);
}

static int capture_root(void *ctx, const char *path, enum vau_content_path_role role)
{
	struct capture *c                     = ctx;
	struct vau_content_path_observation o = { 0 };

	if (strlen(path) >= sizeof(c->root))
		return capture_failed(c, VAU_INVALID);

	strcpy(c->root, path);
	c->role = role;

	int rc = capture_check(c, path);

	if (!rc)
		rc = c->adapter->observe(c->adapter->context, path, &o);
	if (!rc)
		rc = capture_observation_check(c, &o);
	if (!rc && role == VAU_CONTENT_MEDIA_TEMP && o.state != VAU_STATE_DIRECTORY &&
	    o.state != VAU_STATE_MISSING) {
		rc = VAU_DENIED;
	}

	if (!rc)
		rc = vau_content_scope_add(c->writer, path, role, 1, &o);
	if (!rc && o.state == VAU_STATE_DIRECTORY)
		rc = c->adapter->walk(c->adapter->context, path, capture_visit, c);
	return capture_failed(c, rc);
}

static int capture_valid(struct vau_content_scope_writer *w,
                         const struct vau_content_capture_adapter *a)
{
	return w && w->journal && w->journal->scope_active == w->scope.sequence && w->scope.sequence &&
	       !w->failure && a && a->observe && a->walk;
}

int vau_content_capture_vita(struct vau_content_scope_writer *w, const struct vau_file_policy *p,
                             const struct vau_app_install_metadata *m, int shared,
                             const struct vau_content_capture_adapter *a)
{
	if (!capture_valid(w, a) || !p || !a->stopped || vau_policy_validate(p) ||
	    w->scope.request.kind != VAU_CONTENT_APPLICATION ||
	    w->scope.phase == VAU_CONTENT_SCOPE_AFTER) {
		return VAU_INVALID;
	}

	struct capture c = { .writer = w, .adapter = a, .policy = p };

	return capture_failed(
	        &c, vau_content_plan_application(w->scope.request.title, m, shared, capture_root, &c));
}

int vau_content_capture_savedata(struct vau_content_scope_writer *w,
                                 const struct vau_file_policy *p,
                                 const struct vau_app_install_metadata *m, unsigned user,
                                 const char *backup, const struct vau_content_capture_adapter *a)
{
	if (!capture_valid(w, a) || !p || !a->stopped || vau_policy_validate(p) ||
	    w->scope.request.kind != VAU_CONTENT_VITA_SAVEDATA || w->scope.request.user != user ||
	    w->scope.phase == VAU_CONTENT_SCOPE_AFTER) {
		return VAU_INVALID;
	}

	struct capture c = { .writer = w, .adapter = a, .policy = p };

	return capture_failed(&c, vau_content_plan_savedata(w->scope.request.title, m, user, backup,
	                                                    capture_root, &c));
}

int vau_content_capture_media_temp(struct vau_content_scope_writer *w,
                                   const struct vau_file_policy *p,
                                   const struct vau_media_temp_directory *temp,
                                   const struct vau_content_capture_adapter *a)
{
	if (!capture_valid(w, a) || !p || !a->stopped || vau_policy_validate(p) || !temp ||
	    temp->overridden > 1 || !temp->path[0] || !memchr(temp->path, 0, sizeof(temp->path)) ||
	    w->scope.request.kind < VAU_CONTENT_PHOTO || w->scope.phase == VAU_CONTENT_SCOPE_AFTER) {
		return VAU_INVALID;
	}

	struct capture c = { .writer = w, .adapter = a, .policy = p };
	char path[VAU_PATH_MAX];
	int rc = vau_path_normalize(temp->path, path, sizeof(path));

	/* An unrecognized mounted alias needs native mapping proof; don't invent a
	 * physical partition. The default ur0 directory is verified on firmware365.
	 */
	return capture_failed(&c, rc ? rc : capture_root(&c, path, VAU_CONTENT_MEDIA_TEMP));
}

int vau_content_capture_after(struct vau_content_scope_writer *w, uint64_t before,
                              const struct vau_content_capture_adapter *a)
{
	if (!capture_valid(w, a) || w->scope.phase != VAU_CONTENT_SCOPE_AFTER)
		return VAU_INVALID;

	struct capture c = { .writer = w, .adapter = a };
	struct vau_content_scope_page page;
	uint64_t cursor = 0;
	int rc;

	do {
		rc = vau_content_scope_source_page(w, before, cursor, &page);
		if (rc)
			return capture_failed(&c, rc);

		for (unsigned i = 0; i < page.count; i++) {
			struct vau_content_scope_path *p      = &page.entries[i];
			struct vau_content_path_observation o = { 0 };

			rc = a->observe(a->context, p->path, &o);
			if (!rc)
				rc = vau_content_scope_add(w, p->path, p->role, p->root, &o);
			if (rc)
				return capture_failed(&c, rc);
			if (p->root && o.state == VAU_STATE_DIRECTORY) {
				strcpy(c.root, p->path);
				c.role = p->role;
				rc     = a->walk(a->context, p->path, capture_visit, &c);
				if (rc)
					return capture_failed(&c, rc);
			}
		}

		cursor = page.next;
	} while (page.more);
	return 0;
}

struct media_capture {
	struct vau_content_scope_writer *writer;
	const struct vau_file_policy *policy;
	const struct vau_content_capture_adapter *adapter;
	unsigned category, main_count;
};

static int capture_media_failed(struct media_capture *c, int rc)
{
	if (rc && !c->writer->failure)
		c->writer->failure = rc;
	return rc;
}

static int capture_media_file(struct media_capture *c, const char *path,
                              enum vau_content_path_role role, int required)
{
	char normalized[VAU_PATH_MAX];

	if (!path)
		return capture_media_failed(c, VAU_INVALID);

	size_t length = 0;

	while (length < VAU_PATH_MAX && path[length])
		length++;
	if (length == VAU_PATH_MAX || vau_path_normalize(path, normalized, sizeof(normalized)) ||
	    strcmp(path, normalized)) {
		return capture_media_failed(c, VAU_INVALID);
	}

	if (c->adapter->stopped(c->adapter->context))
		return capture_media_failed(c, VAU_EXPIRED);

	enum vau_file_operation op = role == VAU_CONTENT_MEDIA_DATABASE ? VAU_FS_WRITE : VAU_FS_PURGE;

	if (vau_policy_evaluate(c->policy, c->writer->scope.request.subject, op, path, 1) !=
	    VAU_POLICY_ALLOW) {
		return capture_media_failed(c, VAU_DENIED);
	}

	struct vau_content_path_observation observed = { 0 };
	int rc = c->adapter->observe(c->adapter->context, path, &observed);

	if (!rc && !vau_content_path_observation_valid(&observed))
		rc = VAU_DEVICE_ERROR;
	if (!rc && observed.state == VAU_STATE_UNKNOWN)
		rc = observed.error;
	if (!rc && observed.state != VAU_STATE_FILE && observed.state != VAU_STATE_MISSING)
		rc = VAU_DENIED;
	if (!rc && required && observed.state != VAU_STATE_FILE)
		rc = VAU_STALE;
	if (!rc)
		rc = vau_content_scope_add(c->writer, path, role, 1, &observed);
	return capture_media_failed(c, rc);
}

static int capture_media_mapped(void *context, const struct vau_content_media_path *path,
                                unsigned main_file)
{
	struct media_capture *c = context;

	static const char *const roots[] = { "ux0:picture/", "ux0:music/", "ux0:video/" };

	const char *root = roots[c->category - 1];
	size_t n         = strlen(root);

	if (!path || main_file > 1 || !memchr(path->physical, 0, sizeof(path->physical)) ||
	    strncmp(path->physical, root, n) || !path->physical[n]) {
		return capture_media_failed(c, VAU_DENIED);
	}

	if (main_file && c->main_count++)
		return capture_media_failed(c, VAU_STALE);
	return capture_media_file(c, path->physical,
	                          main_file ? VAU_CONTENT_MEDIA_FILE : VAU_CONTENT_MEDIA_RELATED,
	                          main_file);
}

int vau_content_capture_media(struct vau_content_scope_writer *w,
                              const struct vau_file_policy *policy,
                              struct vau_media_session *session,
                              const struct vau_content_media_record *record,
                              const struct vau_content_capture_adapter *adapter)
{
	if (!w || !w->journal || !w->scope.sequence || w->journal->scope_active != w->scope.sequence ||
	    w->failure || !policy || vau_policy_validate(policy) || !session || !session->ready ||
	    session->writable || !vau_content_media_record_valid(record) ||
	    session->category != record->category ||
	    w->scope.request.kind != VAU_CONTENT_PHOTO + record->category - 1 ||
	    w->scope.request.media_id != record->id || w->scope.phase == VAU_CONTENT_SCOPE_AFTER ||
	    !adapter || !adapter->observe || !adapter->stopped) {
		return VAU_INVALID;
	}

	struct media_capture c = { w, policy, adapter, record->category, 0 };

	if (record->status != 2)
		return capture_media_failed(&c, VAU_STALE); /* Native inventory ready predicate. */
	if (adapter->stopped(adapter->context))
		return capture_media_failed(&c, VAU_EXPIRED);

	struct vau_content_media_observation source = { .state = VAU_MEDIA_PRESENT, .record = *record };
	int rc                                      = vau_content_scope_media_add(w, &source);

	static const char *const categories[] = { "photo", "music", "video" };

	char database[96];
	int n = vau_snprintf(database, sizeof(database), "ux0:mms/%s/AVContent.db",
	                     categories[record->category - 1]);

	if (!rc && (n < 0 || (size_t)n + 9 > sizeof(database)))
		rc = VAU_INVALID;
	if (!rc)
		rc = capture_media_file(&c, database, VAU_CONTENT_MEDIA_DATABASE, 1);
	if (!rc) {
		memcpy(database + (size_t)n, "-journal", 9);
		rc = capture_media_file(&c, database, VAU_CONTENT_MEDIA_JOURNAL, 0);
	}

	if (!rc)
		rc = vau_media_session_paths(session, record->path, capture_media_mapped, &c);
	if (!rc && c.main_count != 1)
		rc = VAU_DEVICE_ERROR;
	return capture_media_failed(&c, rc);
}

struct albums {
	struct vau_content_scope_writer *writer;
	sqlite3 *source;
	const struct vau_content_capture_adapter *adapter;
	uint64_t last_list;
	unsigned last_valid;
};

static int capture_albums_fail(struct albums *c, int rc)
{
	if (rc && !c->writer->failure)
		c->writer->failure = rc;
	return rc;
}

static int capture_albums_list(struct albums *c, uint64_t id)
{
	if (c->adapter->stopped(c->adapter->context))
		return VAU_EXPIRED;
	if (c->last_valid && c->last_list == id)
		return 0;

	int known = vau_content_scope_album_list_seen(c->writer, id);

	if (known < 0)
		return known;

	int rc = 0;

	if (!known) {
		struct vau_content_media_list observed;

		rc = vau_content_media_list(c->source, id, c->writer->scope.request.media_id, &observed);
		if (!rc)
			rc = vau_content_scope_album_list_add(c->writer, &observed);
	}

	if (!rc) {
		c->last_list  = id;
		c->last_valid = 1;
	}

	return rc;
}

static int capture_albums_link(void *context, const struct vau_content_media_link *observed)
{
	struct albums *c = context;
	int rc           = capture_albums_list(c, observed->list_id);

	if (!rc)
		rc = vau_content_scope_album_link_add(c->writer, observed);
	return rc;
}

static int capture_albums_old_list(void *context, const struct vau_content_album_entry *entry)
{
	struct albums *c = context;

	if (c->adapter->stopped(c->adapter->context))
		return VAU_EXPIRED;
	return entry->is_list ? capture_albums_list(c, entry->list.id) : 0;
}

int vau_content_capture_media_albums(struct vau_content_scope_writer *w,
                                     struct vau_media_source *source, uint64_t before,
                                     const struct vau_content_capture_adapter *adapter)
{
	if (!w || !w->journal || !w->scope.sequence || w->journal->scope_active != w->scope.sequence ||
	    w->failure || !w->media_added || w->albums_started || w->albums_finished ||
	    w->scope.request.kind < VAU_CONTENT_PHOTO || !source || !source->ready ||
	    !source->transaction || !source->db ||
	    source->category != w->scope.request.kind - VAU_CONTENT_PHOTO + 1 ||
	    source->db == w->journal->db || !adapter || !adapter->stopped ||
	    ((w->scope.phase == VAU_CONTENT_SCOPE_AFTER) != (before != 0))) {
		return VAU_INVALID;
	}

	struct albums c = { .writer = w, .source = source->db, .adapter = adapter };
	int rc          = adapter->stopped(adapter->context) ? VAU_EXPIRED : 0;

	if (!rc) {
		rc = vau_content_media_links(source->db, w->scope.request.media_id, capture_albums_link,
		                             &c);
	}

	if (!rc && before) {
		rc = vau_content_scope_source_albums_visit(w, before, capture_albums_old_list, &c);
		if (rc == 1)
			rc = VAU_STALE; /* Previous memberships were not observed. */
	}

	if (!rc && adapter->stopped(adapter->context))
		rc = VAU_EXPIRED;
	if (!rc)
		rc = vau_content_scope_albums_finish(w);
	return capture_albums_fail(&c, rc);
}

static int capture_media_view_fail(struct vau_content_scope_writer *w, int rc)
{
	if (rc && !w->failure)
		w->failure = rc;
	return rc;
}

int vau_content_capture_media_view(struct vau_content_scope_writer *w,
                                   const struct vau_file_policy *policy,
                                   struct vau_media_session *session,
                                   struct vau_media_source *source, uint64_t before,
                                   const struct vau_content_capture_adapter *adapter)
{
	if (!w || !w->journal || !w->scope.sequence || w->journal->scope_active != w->scope.sequence ||
	    w->failure || w->media_added || w->scope.request.kind < VAU_CONTENT_PHOTO || !source ||
	    !source->ready || !source->transaction || !source->db || source->db == w->journal->db ||
	    source->category != w->scope.request.kind - VAU_CONTENT_PHOTO + 1 || !adapter ||
	    !adapter->observe || !adapter->stopped ||
	    ((w->scope.phase == VAU_CONTENT_SCOPE_AFTER) != (before != 0))) {
		return VAU_INVALID;
	}

	if (w->scope.phase != VAU_CONTENT_SCOPE_AFTER &&
	    (!policy || vau_policy_validate(policy) || !session || !session->ready ||
	     session->writable || session->category != source->category)) {
		return VAU_INVALID;
	}

	if (w->scope.phase == VAU_CONTENT_SCOPE_AFTER && !adapter->walk)
		return VAU_INVALID;
	if (adapter->stopped(adapter->context))
		return capture_media_view_fail(w, VAU_EXPIRED);

	struct vau_content_media_observation observation = { 0 };
	int queried = vau_content_media_record(source->db, source->category, w->scope.request.media_id,
	                                       &observation.record);

	if (w->scope.phase != VAU_CONTENT_SCOPE_AFTER) {
		if (queried)
			return capture_media_view_fail(w, queried == 1 ? VAU_STALE : queried);

		int rc = vau_content_capture_media(w, policy, session, &observation.record, adapter);

		if (!rc)
			rc = vau_content_capture_media_albums(w, source, 0, adapter);
		return capture_media_view_fail(w, rc);
	}

	/* Preserve failed source lookup in the AFTER audit. Absence is distinct
	 * from malformed records/native errors and does not itself prove completion.
	 */
	observation.state = queried == 1 ? VAU_MEDIA_ABSENT
	                    : queried    ? VAU_MEDIA_UNKNOWN
	                                 : VAU_MEDIA_PRESENT;
	observation.error = queried < 0 ? queried : 0;

	int rc = vau_content_scope_media_add(w, &observation);

	if (!rc)
		rc = vau_content_capture_after(w, before, adapter);
	if (!rc)
		rc = vau_content_capture_media_albums(w, source, before, adapter);
	return capture_media_view_fail(w, rc);
}

int vau_content_capture_media_unavailable(struct vau_content_scope_writer *w, uint64_t before,
                                          int native_error,
                                          const struct vau_content_capture_adapter *adapter)
{
	if (!w || !w->journal || !w->scope.sequence || w->journal->scope_active != w->scope.sequence ||
	    w->failure || w->media_added || w->scope.request.kind < VAU_CONTENT_PHOTO ||
	    w->scope.phase != VAU_CONTENT_SCOPE_AFTER || !before || native_error >= 0 || !adapter ||
	    !adapter->observe || !adapter->walk) {
		return VAU_INVALID;
	}

	struct vau_content_media_observation observation = { .state = VAU_MEDIA_UNKNOWN,
		                                                 .error = native_error };
	int rc                                           = vau_content_scope_media_add(w, &observation);
	if (!rc)
		rc = vau_content_capture_after(w, before, adapter);
	/* No album-set marker: memberships were unobserved, never inferred empty.
	 * Preserve the source error while still persisting physical AFTER evidence.
	 */
	return capture_media_view_fail(w, rc);
}

static int stopped(void *ctx)
{
	struct vau_content_capture_native *n = ctx;

	return n->stopped ? n->stopped(n->stop_context) : 0;
}

static void observation(const struct vau_file_info *info, struct vau_content_path_observation *out)
{
	memset(out, 0, sizeof(*out));
	out->info  = *info;
	out->state = info->kind == VAU_FILE_REGULAR     ? VAU_STATE_FILE
	             : info->kind == VAU_FILE_DIRECTORY ? VAU_STATE_DIRECTORY
	                                                : VAU_STATE_OTHER;
}

static int observe(void *ctx, const char *path, struct vau_content_path_observation *out)
{
	(void)ctx;

	struct vau_file_info info = { 0 };
	int rc                    = vau_vita_file_stat(NULL, path, &info);

	if (!rc) {
		observation(&info, out);
	} else {
		memset(out, 0, sizeof(*out));
		if (rc == (int)0x80010002u) {
			out->state = VAU_STATE_MISSING;
		} else {
			out->state = VAU_STATE_UNKNOWN;
			out->error = rc;
		}
	}

	return 0;
}

struct visitor {
	vau_content_capture_visit visit;
	void *context;
};

static int visit(void *ctx, const char *path, const struct vau_file_info *info)
{
	struct visitor *v = ctx;

	struct vau_content_path_observation o;

	observation(info, &o);
	return v->visit(v->context, path, &o);
}

static int walk(void *ctx, const char *path, vau_content_capture_visit callback, void *context)
{
	struct visitor v = { callback, context };

	return vau_native_tree_walk(path, 0, visit, &v, stopped, ctx);
}

void vau_content_capture_native_adapter(struct vau_content_capture_adapter *out,
                                        struct vau_content_capture_native *native)
{
	*out = (struct vau_content_capture_adapter){ native, observe, walk, stopped };
}
