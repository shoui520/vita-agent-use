/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VITA_AGENT_POLICY_H
#define VITA_AGENT_POLICY_H
#include <stddef.h>

#define VAU_PATH_MAX 512u
enum vau_file_operation {
    VAU_FS_READ, VAU_FS_WRITE, VAU_FS_MKDIR, VAU_FS_TRASH,
    VAU_FS_RENAME_SOURCE, VAU_FS_RENAME_DESTINATION, VAU_FS_PURGE,
    VAU_FS_INSTALL /* Audit-only native operation; ordinary write ACLs do not authorize it. */
};
enum vau_policy_decision {
    VAU_POLICY_ALLOW, VAU_POLICY_APPROVAL_REQUIRED, VAU_POLICY_READ_ONLY,
    VAU_POLICY_PROTECTED, VAU_POLICY_NATIVE_OPERATION, VAU_POLICY_INVALID,
    VAU_POLICY_INTENT_REQUIRED
};
/* Lexical normalization only. I/O adapters must additionally reject links and
 * verify resolved mount identity before invoking mutating native operations.
 * Evaluate BOTH paths of a rename/copy; never accept a caller's bypass flag. */
int vau_path_normalize(const char *path, char *out, size_t capacity);
enum vau_policy_decision vau_policy_file(enum vau_file_operation op,
                                        const char *path);

#define VAU_ACL_RULES_MAX 16u
#define VAU_ACL_READ 1u
#define VAU_ACL_WRITE 2u
#define VAU_ACL_ALL (VAU_ACL_READ|VAU_ACL_WRITE)
enum vau_tai_location { VAU_TAI_UNKNOWN,VAU_TAI_UR0,VAU_TAI_UX0,VAU_TAI_UMA0 };
struct vau_acl_rule {
    char subject[65]; /* Lower-case SHA256 identity, or * for all peers. */
    char path[VAU_PATH_MAX];
    unsigned allow,deny;
};
struct vau_file_policy {
    enum vau_tai_location active_tai; /* Trusted native observation only. */
    unsigned count;
    struct vau_acl_rule rules[VAU_ACL_RULES_MAX];
};
/* No allocation; validate the complete trusted ACL before using any rule.
 * Rules cannot override absolute protections. Risk grants must explicitly
 * name a path inside the risky subtree, not an enclosing mount grant.
 * More specific paths win; denies win ties. yes is intent, never a grant. */
int vau_policy_validate(const struct vau_file_policy *policy);
enum vau_policy_decision vau_policy_evaluate(const struct vau_file_policy *policy,
    const char *subject,enum vau_file_operation operation,const char *path,int yes);
int vau_policy_core_plugin(const char *basename);
#endif
