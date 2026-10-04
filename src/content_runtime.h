/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_CONTENT_RUNTIME_H
#define VAU_CONTENT_RUNTIME_H
#include "content_capture.h"
#include "content_sdk.h"
#include "content_delete.h"
int vau_vita_content_promote(const char *);
#include "service.h"
struct vau_content_runtime_io {
    void *context;
    uint64_t (*clock)(void *);
    int (*authorized)(void *, const struct vau_content_delete_request *);
    int (*policy)(void *, struct vau_file_policy *);
    int (*metadata)(void *, const char *, struct vau_app_install_metadata *, int *);
    int (*inspect)(void *, const char *, struct vau_content_observation *);
    int (*approval_begin)(void *, const struct vau_content_delete_request *, int);
    int (*approval_poll)(void *);
    int (*approval_finish)(void *);
    int (*native_start)(void *, const struct vau_content_delete_request *);
    int (*native_poll)(void *, int *);
    struct vau_content_capture_adapter capture, after_capture;
    /* Read-only native media capture; cleanup must finish before success. */
    int (*media_capture)(void *, struct vau_content_scope_writer *, const struct vau_file_policy *,
                         const struct vau_content_capture_adapter *);
    int (*savedata_backup)(void *, unsigned, const char *, struct vau_savedata_backup *);
};
struct vau_content_runtime {
    struct vau_content_delete job;
    struct vau_content_journal *journal;
    struct vau_content_runtime_io io;
    struct vau_file_policy reviewed_policy;
    struct vau_app_install_metadata reviewed_metadata;
    struct vau_savedata_backup reviewed_backup;
    uint64_t preview, before, after, retry_after_us;
    int reviewed, ready_before, shared;
};
/* No filesystem access, dialog, or SDK calls during initialization. Owner is
 * the service thread; the SDK worker only publishes its result. */
int vau_content_runtime_init(struct vau_content_runtime *, struct vau_content_journal *,
                             const struct vau_content_runtime_io *);
int vau_content_runtime_submit(struct vau_content_runtime *, const struct vau_content_delete_request *);
int vau_content_runtime_poll(struct vau_content_runtime *);
int vau_content_runtime_busy(const struct vau_content_runtime *);
int vau_content_runtime_preview(struct vau_content_runtime *, const struct vau_content_delete_request *,
                                struct vau_content_scope *);

void vau_vita_content_init(struct vau_service *);
int vau_vita_content_submit(uint64_t, const struct vau_content_delete_request *,
                            struct vau_content_delete_record *);
int vau_vita_content_status(const char *, const char *, struct vau_content_delete_record *);
int vau_vita_content_busy(void);
int vau_vita_content_inflight(void);
int vau_vita_content_query(void *, uint64_t, const char *, const struct vau_content_query *, char *, size_t);
/* Shared physical UI dispatcher. Poll remains active after network teardown. */
void vau_vita_approval_poll(void *);
void vau_vita_approval_cancel(void *);
int vau_vita_approval_pending(void *);
#endif
