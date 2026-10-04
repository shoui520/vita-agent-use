/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_ACL_CONFIG_H
#define VAU_ACL_CONFIG_H
#include "vita_agent_policy.h"
#define VAU_ACL_CONFIG_BYTES 16384u
/* Owner-installed local configuration only. Active tai is observed by the
 * native adapter and cannot be specified or overridden in this document. */
int vau_acl_config_parse(const char *,size_t,enum vau_tai_location,struct vau_file_policy *);
/* Trusted local OK path only: construct a scoped WRITE grant for one paired
 * identity, preserving other rules and all absolute policy exclusions. */
int vau_acl_grant_prepare(const struct vau_file_policy *,const char *subject,
    const char *path,int directory,struct vau_file_policy *);
int vau_acl_config_format(const struct vau_file_policy *,char *,size_t);
#endif
