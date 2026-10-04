/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_WRITES_VITA_H
#define VAU_WRITES_VITA_H
#include "service.h"
/* Serialized service-thread owner. Initialization performs no filesystem I/O. */
void vau_vita_writes_init(struct vau_service *);
int vau_vita_file_mutate(void *,const struct vau_write_request *,struct vau_write_record *);
int vau_vita_file_upload(void *,const struct vau_upload_message *,struct vau_upload_status *,struct vau_write_record *);
int vau_vita_acl_load(struct vau_file_policy *);
int vau_vita_acl_store(const struct vau_file_policy *);
int vau_vita_acl_audit(const char *,const char *,const char *,const char *,int);
int vau_vita_acl_audit_read(void *,uint32_t,char *,size_t);
#endif
