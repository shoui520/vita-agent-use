/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_ACL_VITA_H
#define VAU_ACL_VITA_H
#include "service.h"
void vau_vita_acl_init(struct vau_service *);
int vau_vita_acl(void *,uint64_t,const char *,const char *,const char *,int,int *,int *);
void vau_vita_acl_poll(void *);
void vau_vita_acl_cancel(void *);
int vau_vita_acl_pending(void *);
#endif
