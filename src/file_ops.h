/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_FILE_OPS_H
#define VAU_FILE_OPS_H
#include "vita_agent_policy.h"
#include "vita_agent.h"
#include <stdint.h>
#define VAU_FILE_READ_BYTES 16384u
enum vau_file_kind { VAU_FILE_OTHER,VAU_FILE_REGULAR,VAU_FILE_DIRECTORY };
struct vau_file_info {
    uint64_t bytes;
    uint32_t mode,attributes,kind;
    uint16_t year,month,day,hour,minute,second;
    uint32_t microsecond;
};
struct vau_file_chunk { uint64_t file_bytes; uint32_t count; struct vau_file_info info; };
typedef int (*vau_file_read_fn)(void *,const char *,uint64_t,void *,uint32_t,struct vau_file_chunk *);
int vau_file_read(vau_file_read_fn native,void *context,const char *path,uint64_t offset,
    void *buffer,uint32_t capacity,struct vau_file_chunk *out);
int vau_vita_file_read(void *context,const char *path,uint64_t offset,void *buffer,
    uint32_t capacity,struct vau_file_chunk *out);
typedef int (*vau_file_stat_fn)(void *,const char *,struct vau_file_info *);
#define VAU_FILE_PAGE_ENTRIES 8u
#define VAU_FILE_PAGE_JSON_BYTES 3072u
#define VAU_FILE_OFFSET_MAX UINT32_MAX
#define VAU_FILE_LIST_SCAN_READS 128u
struct vau_file_entry { char name[256]; struct vau_file_info info; };
struct vau_file_page {
    struct vau_file_entry entries[VAU_FILE_PAGE_ENTRIES];
    uint32_t count,next_offset;
    int more;
};
typedef int (*vau_file_list_fn)(void *,const char *,uint32_t,struct vau_file_page *);
int vau_file_list(vau_file_list_fn native,void *context,const char *path,uint32_t offset,struct vau_file_page *out);
int vau_vita_file_list(void *context,const char *path,uint32_t offset,struct vau_file_page *out);
/* One serialized native directory continuation, bounded resident storage.
 * Close on idle/session shutdown and before native mutations. */
int vau_vita_file_list_reset(void);
void vau_vita_file_list_idle(uint64_t now);
/* On-device read policy before native I/O. Adapter rejects links reported by native stat in
 * each component; no generic file operation may inspect private control data. */
int vau_file_stat(vau_file_stat_fn native,void *context,const char *path,struct vau_file_info *out);
int vau_vita_file_stat(void *context,const char *path,struct vau_file_info *out);
#endif
