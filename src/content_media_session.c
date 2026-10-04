/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "content_media.h"
#include "native_ops.h"
#include <string.h>
void vau_media_session_init(struct vau_media_session *s, const struct vau_media_session_backend *backend) {
    memset(s, 0, sizeof(*s));
    if (backend)
        s->backend = *backend;
    vau_media_db_init(&s->database, &s->backend.database);
    vau_media_modules_init(&s->modules, s->backend.context, s->backend.module_resolve, s->backend.stopped);
}
static int stopped(struct vau_media_session *s) {
    return s->backend.stopped && s->backend.stopped(s->backend.context);
}
static int teardown(struct vau_media_session *s) {
    /* All operation/profiler owners are destroyed synchronously before returning
     * to the session. Discard cached exports before releasing module references. */
    int rc = 0;
    if (s->path_active) {
        rc = s->backend.path_end(s->backend.context);
        if (!rc)
            s->path_active = 0;
    }
    memset(&s->operation, 0, sizeof(s->operation));
    memset(&s->profiler, 0, sizeof(s->profiler));
    int end = vau_media_modules_release(&s->modules);
    if (!rc)
        rc = end;
    end = 0;
    if (s->mount_active) {
        end = s->backend.mount_end(s->backend.context);
        if (!end)
            s->mount_active = 0;
        if (!rc)
            rc = end;
    }
    end = vau_media_db_close(&s->database);
    if (!rc)
        rc = end;
    s->category = s->writable = s->ready = 0;
    return rc;
}
int vau_media_session_open(struct vau_media_session *s, unsigned category, int writable) {
    if (!s || category < 1 || category > 3 || (writable != 0 && writable != 1) ||
        !s->backend.prepare_memory || !s->backend.allocate || !s->backend.release ||
        (!!s->backend.mount_begin != !!s->backend.mount_end) ||
        (!!s->backend.path_begin != !!s->backend.path_end))
        return VAU_INVALID;
    if (s->busy || s->ready || s->mount_active || s->path_active)
        return VAU_BUSY;
    s->busy = 1;
    int rc = stopped(s) ? VAU_EXPIRED : vau_media_db_open(&s->database, category, writable);
    if (!rc && s->backend.mount_begin) {
        /* A failed begin can still have acquired ownership. Its matching end
         * is mandatory, and failed teardown remains pending for close retry. */
        s->mount_active = 1;
        rc = stopped(s) ? VAU_EXPIRED : s->backend.mount_begin(s->backend.context, category);
    }
    if (!rc)
        rc = stopped(s) ? VAU_EXPIRED : vau_media_modules_acquire(&s->modules, category);
    if (!rc)
        rc = stopped(s) ? VAU_EXPIRED : s->backend.prepare_memory(s->backend.context);
    if (!rc && stopped(s))
        rc = VAU_EXPIRED;
    if (!rc) {
        vau_media_sdk_init(&s->operation, &s->backend.operation, s->backend.context, s->backend.allocate,
                           s->backend.release);
        vau_media_profiler_init(&s->profiler, &s->backend.profiler, s->backend.context, s->backend.release,
                                s->backend.stopped);
        if (category == 3)
            rc = vau_media_profiler_prepare(&s->profiler);
        if (!rc) {
            s->category = category;
            s->writable = (unsigned)writable;
            s->ready = 1;
        }
    }
    if (rc)
        (void)teardown(s);
    s->busy = 0;
    return rc;
}
static int walk_paths(struct vau_media_session *s, const char *path, vau_media_related_visit visit,
                      void *context, int (*main_file)(void *, const char *)) {
    if (!s || !s->ready || !path || !visit)
        return VAU_INVALID;
    if (s->busy || s->path_active)
        return VAU_BUSY;
    if (s->category != 3 && !main_file)
        return VAU_UNSUPPORTED;
    s->busy = 1;
    const char *resolved = path;
    int rc = stopped(s) ? VAU_EXPIRED : 0;
    if (!rc && s->backend.path_begin) {
        s->path_active = 1;
        resolved = NULL;
        rc = s->backend.path_begin(s->backend.context, path, &resolved);
        if (!rc && !resolved)
            rc = VAU_DEVICE_ERROR;
    }
    if (!rc && main_file)
        rc = main_file(context, resolved);
    if (!rc && s->category == 3)
        rc = vau_media_profiler_walk(&s->profiler, resolved, visit, context);
    if (s->path_active) {
        int end = s->backend.path_end(s->backend.context);
        if (!end)
            s->path_active = 0;
        if (!rc)
            rc = end;
    }
    s->busy = 0;
    return rc;
}
int vau_media_session_related(struct vau_media_session *s, const char *path, vau_media_related_visit visit,
                              void *context) {
    return walk_paths(s, path, visit, context, NULL);
}
struct mapped_paths {
    struct vau_media_session *session;
    vau_media_path_visit visit;
    void *context;
};
static int mapped_path(struct mapped_paths *m, const char *path, unsigned main_file) {
    if (stopped(m->session))
        return VAU_EXPIRED;
    struct vau_content_media_path mapped = {0};
    int rc = m->session->backend.resolve_path(m->session->backend.context, path, &mapped);
    if (!rc && stopped(m->session))
        rc = VAU_EXPIRED;
    if (!rc)
        rc = m->visit(m->context, &mapped, main_file);
    return rc;
}
static int mapped_main(void *context, const char *path) { return mapped_path(context, path, 1); }
static int mapped_related(void *context, const char *path, size_t bytes) {
    (void)bytes;
    return mapped_path(context, path, 0);
}
int vau_media_session_paths(struct vau_media_session *s, const char *path, vau_media_path_visit visit,
                            void *context) {
    if (!s || !visit)
        return VAU_INVALID;
    if (!s->backend.resolve_path)
        return VAU_UNSUPPORTED;
    char native_path[VAU_PATH_MAX];
    int rc = vau_content_media_operation_path(s->category, path, native_path, sizeof(native_path));
    if (rc)
        return rc;
    struct mapped_paths m = {s, visit, context};
    return walk_paths(s, native_path, mapped_related, &m, mapped_main);
}
int vau_media_session_video_paths(struct vau_media_session *s, const char *path, vau_media_path_visit visit,
                                  void *context) {
    if (!s || !visit)
        return VAU_INVALID;
    if (s->ready && s->category != 3)
        return VAU_UNSUPPORTED;
    return vau_media_session_paths(s, path, visit, context);
}
int vau_media_session_remove(struct vau_media_session *s, uint64_t id) {
    if (!s || !s->ready || !id || id > INT64_MAX)
        return VAU_INVALID;
    if (s->busy)
        return VAU_BUSY;
    if (s->path_active)
        return VAU_BUSY;
    if (!s->writable)
        return VAU_DENIED;
    s->busy = 1;
    int rc = stopped(s)
                 ? VAU_EXPIRED
                 : vau_media_sdk_remove(&s->operation, vau_media_db_context(&s->database), s->category, id);
    s->busy = 0;
    return rc;
}
int vau_media_session_close(struct vau_media_session *s) {
    if (!s)
        return VAU_INVALID;
    if (s->busy || s->operation.busy || s->profiler.busy)
        return VAU_BUSY;
    s->busy = 1;
    int rc = teardown(s);
    s->busy = 0;
    return rc;
}
