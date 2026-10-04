/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_SQLITE_VFS_H
#define VAU_SQLITE_VFS_H
int vau_sqlite_vfs_configure(void);
int vau_sqlite_vfs_native_error(void);
#define VAU_JOURNAL_VFS "vita-agent-audit"
#endif
