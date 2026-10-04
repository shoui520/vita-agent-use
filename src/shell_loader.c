/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <psp2/sysmodule.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <stdio.h>
static void report(const char *stage,int result)
{
    char line[96]; int n=snprintf(line,sizeof(line),"%s: %d\n",stage,result);
    if(n<=0 || (size_t)n>=sizeof(line)) return;
    int fd=sceIoOpen("ur0:data/vita-agent-use/loader.log",SCE_O_WRONLY|SCE_O_CREAT|SCE_O_APPEND,0666);
    if(fd<0)
        fd=sceIoOpen("ux0:data/vita-agent-use-loader.log",SCE_O_WRONLY|SCE_O_CREAT|SCE_O_APPEND,0666);
    if(fd>=0) { (void)sceIoWrite(fd,line,n); (void)sceIoClose(fd); }
}
static int load_service(SceSize argc,void *args)
{
    (void)argc; (void)args;
    /* Wait on our thread, never during Shell's module_start. Shell owns Net. */
    sceKernelDelayThread(2000000);
    SceIoStat st={0};
    int directory=sceIoGetstat("ur0:data/vita-agent-use",&st);
    if((unsigned)directory==0x80010002u) directory=sceIoMkdir("ur0:data/vita-agent-use",0777);
    report("loader directory",directory);
    report("loader worker started",0);
    int rc=sceSysmoduleIsLoaded(SCE_SYSMODULE_NOTIFICATION_UTIL);
    report("notification module query",rc);
    if(rc<0) {
        report("notification module loading",0);
        rc=sceSysmoduleLoadModule(SCE_SYSMODULE_NOTIFICATION_UTIL);
        report("notification module loaded",rc);
    }
    if(rc>=0) {
        rc=sceSysmoduleIsLoaded(SCE_SYSMODULE_SQLITE);
        if(rc<0) rc=sceSysmoduleLoadModule(SCE_SYSMODULE_SQLITE);
        report("SQLite module ready",rc);
    }
    if(rc>=0) {
        int status=0;
        report("Shell service loading",0);
        rc=sceKernelLoadStartModule("ur0:tai/vita_agent_shell.suprx",0,NULL,0,NULL,&status);
        report("Shell service module result",rc);
        report("Shell service start result",status);
        if(rc>=0 && status<0) rc=status;
    }
    report("Shell service load",rc);
    return 0;
}
int _start(SceSize argc,const void *args) __attribute__((weak,alias("module_start")));
int module_start(SceSize argc,const void *args)
{
    (void)argc; (void)args;
    int thread=sceKernelCreateThread("VauLoader",load_service,0x10000100,32*1024,0,0,NULL);
    if(thread<0) return SCE_KERNEL_START_FAILED;
    if(sceKernelStartThread(thread,0,NULL)<0) { sceKernelDeleteThread(thread); return SCE_KERNEL_START_FAILED; }
    return SCE_KERNEL_START_SUCCESS;
}
int module_stop(SceSize argc,const void *args)
{ (void)argc; (void)args; return SCE_KERNEL_STOP_CANCEL; }
