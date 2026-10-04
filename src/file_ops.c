/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "file_ops.h"
#include "json.h"
#include <string.h>
int vau_file_stat(vau_file_stat_fn native,void *context,const char *path,struct vau_file_info *out)
{
    if (!out) return VAU_INVALID;
    memset(out,0,sizeof(*out));
    char normalized[VAU_PATH_MAX];
    if (vau_path_normalize(path,normalized,sizeof(normalized))) return VAU_INVALID;
    if (vau_policy_file(VAU_FS_READ,normalized)!=VAU_POLICY_ALLOW) return VAU_DENIED;
    if (!native) return VAU_UNSUPPORTED;
    int rc=native(context,normalized,out);
    if (rc<0 || out->kind>VAU_FILE_DIRECTORY) {
        memset(out,0,sizeof(*out)); return rc<0 ? rc : VAU_DEVICE_ERROR;
    }
    return VAU_OK;
}

int vau_file_list(vau_file_list_fn native,void *context,const char *path,uint32_t offset,struct vau_file_page *out)
{
    if (!out) return VAU_INVALID;
    memset(out,0,sizeof(*out));
    char normalized[VAU_PATH_MAX];
    if (offset>VAU_FILE_OFFSET_MAX || vau_path_normalize(path,normalized,sizeof(normalized))) return VAU_INVALID;
    if (vau_policy_file(VAU_FS_READ,normalized)!=VAU_POLICY_ALLOW) return VAU_DENIED;
    if (!native) return VAU_UNSUPPORTED;
    int rc=native(context,normalized,offset,out);
    if (rc<0 || out->count>VAU_FILE_PAGE_ENTRIES || out->next_offset<offset ||
        out->next_offset>VAU_FILE_OFFSET_MAX || (out->more!=0 && out->more!=1)) {
        memset(out,0,sizeof(*out)); return rc<0 ? rc : VAU_DEVICE_ERROR;
    }
    size_t json_bytes=0;
    for (uint32_t i=0;i<out->count;i++) {
        char quoted[1533];
        if (!memchr(out->entries[i].name,0,sizeof(out->entries[i].name)) ||
            out->entries[i].info.kind>VAU_FILE_DIRECTORY) { memset(out,0,sizeof(*out)); return VAU_DEVICE_ERROR; }
        int encoded=vau_json_quote(out->entries[i].name,quoted,sizeof(quoted));
        if (encoded<0) { memset(out,0,sizeof(*out)); return VAU_DEVICE_ERROR; }
        json_bytes+=(size_t)encoded+128u;
    }
    if (json_bytes>VAU_FILE_PAGE_JSON_BYTES) { memset(out,0,sizeof(*out)); return VAU_DEVICE_ERROR; }
    return VAU_OK;
}

int vau_file_read(vau_file_read_fn native,void *context,const char *path,uint64_t offset,
    void *buffer,uint32_t capacity,struct vau_file_chunk *out)
{
    if (!out || !buffer || !capacity || capacity>VAU_FILE_READ_BYTES || offset>INT64_MAX) return VAU_INVALID;
    memset(out,0,sizeof(*out));
    char normalized[VAU_PATH_MAX];
    if (vau_path_normalize(path,normalized,sizeof(normalized))) return VAU_INVALID;
    if (vau_policy_file(VAU_FS_READ,normalized)!=VAU_POLICY_ALLOW) return VAU_DENIED;
    if (!native) return VAU_UNSUPPORTED;
    int rc=native(context,normalized,offset,buffer,capacity,out);
    if (rc<0 || out->count>capacity || offset>out->file_bytes ||
        out->count>out->file_bytes-offset || out->info.kind!=VAU_FILE_REGULAR) {
        memset(buffer,0,capacity); memset(out,0,sizeof(*out)); return rc<0 ? rc : VAU_DEVICE_ERROR;
    }
    return VAU_OK;
}
