/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "native_ops.h"
#include "sqlite_json.h"
#include "json.h"
#include "format.h"
#include <string.h>
#ifdef VAU_NATIVE_FORMAT
#include "sqlite_memory.h"
#endif
int vau_livearea_blob(const char *path,const char *section,const char *page,uint32_t position,const char *column,uint32_t offset,char *out,size_t cap)
{
    if(!path || !section || !page || !column || !out || cap<3500)return VAU_INVALID;
    int icons=!strcmp(section,"icons");if(!icons && strcmp(section,"pages"))return VAU_INVALID;
    if(strlen(page)>20 || !page[0] || (page[0]=='-' && !page[1]))return VAU_INVALID;
    const char *digits=page+(page[0]=='-');
    if((digits[0]=='0' && digits[1]) || !strcmp(page,"-0"))return VAU_INVALID;
    struct vau_json_token number={0,strlen(digits),0,VAU_JSON_NUMBER};uint64_t id;
    if(vau_json_u64(digits,&number,&id) || id>(uint64_t)INT64_MAX+(page[0]=='-'))return VAU_INVALID;
    static const char *columns[]={"reserved01","reserved02","reserved03","reserved04","reserved05"};unsigned found;
    for(found=0;found<5;found++)if(!strcmp(column,columns[found]))break;
    if(found==5 || position>INT32_MAX)return VAU_INVALID;
#ifdef VAU_NATIVE_FORMAT
    int configured=vau_sqlite_memory_configure();if(configured)return configured;
#endif
    vau_sqlite_json_reset();sqlite3 *db=NULL;sqlite3_stmt *stmt=NULL;
    char sql[512];int n=vau_snprintf(sql,sizeof(sql),"SELECT length(%s),substr(%s,CAST(?3 AS INTEGER)+1,512) FROM %s WHERE pageId=CAST(?1 AS INTEGER)%s AND typeof(%s)='blob'",columns[found],columns[found],icons ? "tbl_appinfo_icon":"tbl_appinfo_page",icons ? " AND pos=CAST(?2 AS INTEGER)":"",columns[found]);
    if(n<0 || (size_t)n>=sizeof(sql))return VAU_INVALID;
    int rc=sqlite3_open_v2(path,&db,1,NULL);if(rc)goto done;
    rc=sqlite3_exec(db,"PRAGMA cache_size=32",NULL,NULL,NULL);if(rc)goto done;
    rc=sqlite3_prepare_v2(db,sql,-1,&stmt,NULL);if(rc)goto done;
    rc=sqlite3_bind_text(stmt,1,page,-1,NULL);if(rc)goto done;
    char pos[16],at[16];vau_snprintf(pos,sizeof(pos),"%u",position);vau_snprintf(at,sizeof(at),"%u",offset);
    if(icons){rc=sqlite3_bind_text(stmt,2,pos,-1,NULL);if(rc)goto done;}
    rc=sqlite3_bind_text(stmt,3,at,-1,NULL);if(rc)goto done;
    rc=sqlite3_step(stmt);if(rc==101){rc=VAU_STALE;goto done;}if(rc!=100)goto done;
    const unsigned char *size=sqlite3_column_text(stmt,0);int size_bytes=sqlite3_column_bytes(stmt,0);uint64_t bytes;
    number=(struct vau_json_token){0,(size_t)(size_bytes>0 ? size_bytes:0),0,VAU_JSON_NUMBER};
    if(!size || vau_json_u64((const char *)size,&number,&bytes) || bytes>INT64_MAX || offset>bytes){rc=VAU_INVALID;goto done;}
    int count=sqlite3_column_bytes(stmt,1);
    if(count<0 || count>512 || (uint64_t)count!=(bytes-offset<512 ? bytes-offset:512)){rc=VAU_STALE;goto done;}
    n=vau_snprintf(out,cap,"{\"source\":\"native_livearea_database\",\"snapshot\":false,\"offset\":%u,\"next_offset\":%u,\"bytes\":\"%llu\",\"more\":%s,\"chunk\":",offset,offset+(unsigned)count,(unsigned long long)bytes,(uint64_t)offset+count<bytes ? "true":"false");
    if(n<0 || (size_t)n>=cap){rc=VAU_UNSUPPORTED;goto done;}
    int added=vau_sqlite_json_column(stmt,1,out+n,cap-(size_t)n,0);if(added<0){rc=added;goto done;}n+=added;
    if((size_t)n+2>cap){rc=VAU_UNSUPPORTED;goto done;}out[n++]='}';out[n]=0;rc=0;
done:
    if(stmt){int end=sqlite3_finalize(stmt);if(!rc && end)rc=end;}
    if(db){int end=sqlite3_close(db);if(!rc && end)rc=end;}
    return rc ? rc<0 ? rc:VAU_DEVICE_ERROR:n;
}
int vau_vita_livearea_blob(void *ctx,const char *section,const char *page,uint32_t position,const char *column,uint32_t offset,char *out,size_t cap)
{(void)ctx;return vau_livearea_blob("ur0:shell/db/app.db",section,page,position,column,offset,out,cap);}
