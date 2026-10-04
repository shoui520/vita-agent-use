/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "sqlite_vfs.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <stdint.h>
#include <string.h>
/* Public SQLite version-1 VFS ABI. This private VFS has one serialized owner,
 * accepts only our journal and rollback sidecar, and is never the default. */
typedef int64_t sql_int64;
struct sql_file;
struct sql_methods {
    int version;
    int (*close)(struct sql_file *);
    int (*read)(struct sql_file *,void *,int,sql_int64);
    int (*write)(struct sql_file *,const void *,int,sql_int64);
    int (*truncate)(struct sql_file *,sql_int64);
    int (*sync)(struct sql_file *,int);
    int (*size)(struct sql_file *,sql_int64 *);
    int (*lock)(struct sql_file *,int);
    int (*unlock)(struct sql_file *,int);
    int (*reserved)(struct sql_file *,int *);
    int (*control)(struct sql_file *,int,void *);
    int (*sector)(struct sql_file *);
    int (*characteristics)(struct sql_file *);
};
struct sql_file { const struct sql_methods *methods;int fd,lock,main; };
struct sql_vfs {
    int version,file_size,path_max;struct sql_vfs *next;const char *name;void *context;
    int (*open)(struct sql_vfs *,const char *,struct sql_file *,int,int *);
    int (*remove)(struct sql_vfs *,const char *,int);
    int (*access)(struct sql_vfs *,const char *,int,int *);
    int (*fullpath)(struct sql_vfs *,const char *,int,char *);
    void *(*dlopen)(struct sql_vfs *,const char *);
    void (*dlerror)(struct sql_vfs *,int,char *);
    void (*(*dlsym)(struct sql_vfs *,void *,const char *))(void);
    void (*dlclose)(struct sql_vfs *,void *);
    int (*random)(struct sql_vfs *,int,char *);
    int (*sleep)(struct sql_vfs *,int);
    int (*time)(struct sql_vfs *,double *);
    int (*error)(struct sql_vfs *,int,char *);
};
extern struct sql_vfs *sqlite3_vfs_find(const char *);
extern int sqlite3_vfs_register(struct sql_vfs *,int);
static const char journal[]="ur0:data/vita-agent-use/write-audit.db";
static struct sql_file *main_file;
static int native_error;
int vau_sqlite_vfs_native_error(void) { return native_error; }
static int allowed(const char *p)
{ return p && (!strcmp(p,journal) || !strcmp(p,"ur0:data/vita-agent-use/write-audit.db-journal")); }
static int close_file(struct sql_file *f)
{ int rc=sceIoClose(f->fd);if(main_file==f)main_file=NULL;f->methods=NULL;return rc<0 ? 10:0; }
static int read_file(struct sql_file *f,void *buffer,int bytes,sql_int64 offset)
{
    if(bytes<0 || offset<0 || sceIoLseek(f->fd,offset,SCE_SEEK_SET)!=offset)return 10;
    int used=0;
    while(used<bytes) {int n=sceIoRead(f->fd,(char *)buffer+used,(unsigned)(bytes-used));
        if(n<0 || n>bytes-used)return 10;
        if(!n){memset((char *)buffer+used,0,(size_t)(bytes-used));return 10|(2<<8);}used+=n;}
    return 0;
}
static int write_file(struct sql_file *f,const void *buffer,int bytes,sql_int64 offset)
{
    if(bytes<0 || offset<0 || sceIoLseek(f->fd,offset,SCE_SEEK_SET)!=offset)return 10|(3<<8);
    int used=0;
    while(used<bytes) {int n=sceIoWrite(f->fd,(const char *)buffer+used,(unsigned)(bytes-used));
        if(n<=0 || n>bytes-used)return 10|(3<<8);
        used+=n;}
    return 0;
}
static int truncate_file(struct sql_file *f,sql_int64 bytes)
{ SceIoStat s={0};s.st_size=bytes;return bytes<0 || sceIoChstatByFd(f->fd,&s,8)<0 ? 10|(6<<8):0; }
static int sync_file(struct sql_file *f,int flags)
{ (void)flags;return sceIoSyncByFd(f->fd,0)<0 ? 10|(4<<8):0; }
static int size_file(struct sql_file *f,sql_int64 *bytes)
{ SceIoStat s;int rc=sceIoGetstatByFd(f->fd,&s);if(rc<0)return 10|(7<<8);*bytes=s.st_size;return 0; }
static int lock_file(struct sql_file *f,int level) { f->lock=level;return 0; }
static int reserved_file(struct sql_file *f,int *out) { *out=main_file && main_file!=f && main_file->lock>=2;return 0; }
static int control_file(struct sql_file *f,int op,void *out)
{ if(op==1){*(int *)out=f->lock;return 0;}return 12; }
static int sector_file(struct sql_file *f) { (void)f;return 4096; }
static int characteristics_file(struct sql_file *f) { (void)f;return 0; }
static const struct sql_methods methods={1,close_file,read_file,write_file,truncate_file,sync_file,size_file,
    lock_file,lock_file,reserved_file,control_file,sector_file,characteristics_file};
static int open_file(struct sql_vfs *v,const char *path,struct sql_file *f,int flags,int *out)
{
    (void)v;native_error=0;memset(f,0,sizeof(*f));
    if(!allowed(path) || (flags&8) || ((flags&0x100) && main_file))return 14;
    int native=flags&2 ? SCE_O_RDWR:SCE_O_RDONLY;
    if(flags&4)native|=SCE_O_CREAT;
    if(flags&16)native|=SCE_O_EXCL;
    int fd=sceIoOpen(path,native,0666);if(fd<0){native_error=fd;return 14;}
    f->fd=fd;f->main=!!(flags&0x100);f->methods=&methods;if(f->main)main_file=f;
    if(out)*out=flags;
    return 0;
}
static int remove_file(struct sql_vfs *v,const char *path,int sync)
{
    (void)v;if(!allowed(path) || !strcmp(path,journal))return 10|(10<<8);
    int rc=sceIoRemove(path);if(rc<0 && (uint32_t)rc!=0x80010002u)return 10|(10<<8);
    return sync && sceIoSync("ur0:",0)<0 ? 10|(5<<8):0;
}
static int access_file(struct sql_vfs *v,const char *path,int flags,int *out)
{
    (void)v;(void)flags;*out=0;if(!allowed(path))return 0; /* Unsupported WAL/temp files are absent. */
    SceIoStat s;int rc=sceIoGetstat(path,&s);if((uint32_t)rc==0x80010002u)return 0;
    if(rc<0)return 10|(13<<8);
    *out=SCE_S_ISREG(s.st_mode);return 0;
}
static int fullpath(struct sql_vfs *v,const char *path,int capacity,char *out)
{ (void)v;if(!allowed(path) || capacity<=0 || strlen(path)>=(size_t)capacity)return 14;memcpy(out,path,strlen(path)+1);return 0; }
int vau_sqlite_vfs_configure(void)
{
    static struct sql_vfs v;static int configured;
    if(configured)return 0;
    struct sql_vfs *base=sqlite3_vfs_find(NULL);if(!base)return 14;
    memcpy(&v,base,sizeof(v));v.version=1;v.file_size=sizeof(struct sql_file);v.next=NULL;v.name=VAU_JOURNAL_VFS;
    v.open=open_file;v.remove=remove_file;v.access=access_file;v.fullpath=fullpath;
    int rc=sqlite3_vfs_register(&v,0);if(!rc)configured=1;return rc;
}
