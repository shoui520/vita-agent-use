/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "file_mutations.h"
#include "file_ops.h"
#include <string.h>
int vau_write_observe(const char *path,struct vau_write_observation *out)
{
    memset(out,0,sizeof(*out));struct vau_file_info info;int rc=vau_vita_file_stat(NULL,path,&info);
    if(rc==(int)0x80010002u){out->state=VAU_STATE_MISSING;return VAU_OK;}
    if(rc)return rc;
    out->state=info.kind==VAU_FILE_REGULAR ? VAU_STATE_FILE:info.kind==VAU_FILE_DIRECTORY ? VAU_STATE_DIRECTORY:VAU_STATE_OTHER;
    out->bytes=info.bytes;return VAU_OK;
}
