/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_STAGED_UPLOAD_H
#define VAU_STAGED_UPLOAD_H
#include "write_journal.h"
struct vau_upload_context {
    const struct vau_file_policy *policy;
    struct vau_write_journal *journal;
    void *context;
    int (*stopped)(void *);
    uint64_t (*clock)(void *);
    int (*config_check)(struct vau_upload_context *,const struct vau_write_request *,const char *stage);
    /* Guarded native replacement with retained original, journaled recovery
     * and explicit readback. Missing callback disables config commit. */
    int (*config_replace)(struct vau_upload_context *,const struct vau_write_request *,const char *stage,unsigned *started);
};
struct vau_upload_status { uint64_t received;unsigned verified; };
/* Internal native adapter: no stage path is accepted from the peer. The
 * authenticated dispatcher must supply the immutable peer identity. */
int vau_upload_config_replace(struct vau_upload_context *,const struct vau_write_request *,const char *,unsigned *);
int vau_upload_commit(struct vau_upload_context *,const struct vau_write_request *,struct vau_write_record *);
int vau_upload_recover(struct vau_upload_context *,const struct vau_write_request *,struct vau_write_record *);
int vau_upload_stage_path(const struct vau_write_request *,char [VAU_PATH_MAX]);
int vau_upload_begin(struct vau_upload_context *,const struct vau_write_request *,struct vau_upload_status *);
int vau_upload_chunk(struct vau_upload_context *,const struct vau_write_request *,uint64_t,
    const void *,uint32_t,struct vau_upload_status *);
int vau_upload_verify(struct vau_upload_context *,const struct vau_write_request *,struct vau_upload_status *);
int vau_upload_file_digest(struct vau_upload_context *,const char *,char [65]);
#endif
