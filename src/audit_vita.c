/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "audit_export.h"
#include "file_ops.h"
int vau_vita_audit_export(void *context,uint64_t after,char *output,size_t capacity)
{
    (void)context;
    /* Export must not create a journal. The write service owns initialization
     * and recovery; missing/uninitialized journals are reported explicitly. */
    const char *path="ur0:data/vita-agent-use/write-audit.db";
    struct vau_file_info info;int rc=vau_vita_file_stat(NULL,path,&info);if(rc)return rc;
    if(info.kind!=VAU_FILE_REGULAR)return VAU_DENIED;
    struct vau_write_journal j={0};rc=vau_journal_open_readonly(&j,path);if(rc)return rc;
    rc=vau_audit_export(&j,after,output,capacity);
    int closed=vau_journal_close(&j);return closed ? closed:rc;
}
