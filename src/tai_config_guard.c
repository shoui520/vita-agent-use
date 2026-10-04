/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "tai_config_guard.h"
#include "vita_agent_policy.h"
#include "vita_agent.h"
#include <string.h>
/* taiHEN lexer uses CR or LF as line separators, trims C whitespace, and
 * limits a physical line to 255 bytes. Section ! halts only on the next
 * section token while that halted section is selected. */
struct span { const unsigned char *p;size_t n; };
struct scan { const unsigned char *p;size_t n,at;struct span section;int halt; };
struct line { struct span text,section;int kind,halt; };
static int space(unsigned char c) { return c==' ' || c=='\t' || c=='\v' || c=='\f' || c=='\r'; }
static int equal(struct span a,struct span b) { return a.n==b.n && (!a.n || !memcmp(a.p,b.p,a.n)); }
static int word(struct span a,const char *b) { return a.n==strlen(b) && !memcmp(a.p,b,a.n); }
static int utf8(const unsigned char *p,size_t n)
{
    for(size_t i=0;i<n;) {
        unsigned c=p[i++],extra=0,min=0,value=c;
        if (c<128) { if (!c || c==127 || (c<32 && c!='\n' && !space((unsigned char)c))) return 0;continue; }
        if(c>=0xc2 && c<=0xdf) {extra=1;min=0x80;value=c&31;}
        else if(c>=0xe0 && c<=0xef) {extra=2;min=0x800;value=c&15;}
        else if(c>=0xf0 && c<=0xf4) {extra=3;min=0x10000;value=c&7;}
        else return 0;
        if(extra>n-i)return 0;
        while(extra--) {c=p[i++];if((c&0xc0)!=0x80)return 0;value=(value<<6)|(c&63);}
        if(value<min || value>0x10ffff || (value>=0xd800 && value<=0xdfff))return 0;
    }
    return 1;
}
static int next(struct scan *s,struct line *out)
{
    if(s->at>=s->n)return 0;
    size_t begin=s->at;
    while(s->at<s->n && s->p[s->at]!='\n' && s->p[s->at]!='\r')++s->at;
    size_t end=s->at;if(s->at<s->n)++s->at;
    if(end-begin>=256)return VAU_INVALID;
    while(begin<end && space(s->p[begin]))++begin;
    while(end>begin && space(s->p[end-1]))--end;
    *out=(struct line){.text={s->p+begin,end-begin},.section=s->section};
    if(begin==end || s->p[begin]=='#')return 1;
    if(s->p[begin]=='*') {
        ++begin;while(begin<end && space(s->p[begin]))++begin;
        int halt=begin<end && s->p[begin]=='!';
        if(halt){++begin;while(begin<end && space(s->p[begin]))++begin;}
        if(begin==end)return VAU_INVALID;
        s->section=(struct span){s->p+begin,end-begin};s->halt=halt;
        out->kind=2;out->section=s->section;out->halt=halt;
    } else {
        if(!s->section.n)return VAU_INVALID;
        out->kind=1;out->halt=s->halt;
    }
    return 1;
}
static int critical(struct span line)
{
    char name[256];size_t start=0;
    /* Protect commented-out core entries too: uncommenting is a change. */
    while(start<line.n && (line.p[start]=='#' || space(line.p[start])))++start;
    for(size_t i=start;i<line.n;++i)if(line.p[i]=='/' || line.p[i]==':')start=i+1;
    size_t end=line.n;while(end>start && space(line.p[end-1]))--end;
    if(end-start>=sizeof(name))return 0;
    memcpy(name,line.p+start,end-start);name[end-start]=0;
    return vau_policy_core_plugin(name);
}
static int validate(const unsigned char *p,size_t n)
{
    if(!p || n>VAU_TAI_CONFIG_BYTES || !utf8(p,n))return VAU_INVALID;
    struct scan s={.p=p,.n=n};struct line l;int rc;
    while((rc=next(&s,&l))>0) {
        if(l.kind==1) {
            char path[256],normalized[VAU_PATH_MAX];
            memcpy(path,l.text.p,l.text.n);path[l.text.n]=0;
            if(vau_path_normalize(path,normalized,sizeof(normalized)))return VAU_INVALID;
        }
    }
    return rc;
}
static int next_critical(struct scan *s,struct line *out)
{
    int rc;while((rc=next(s,out))>0)if(critical(out->text))return 1;
    return rc;
}
static int effective(struct scan *s,struct span target,struct span *out,int *selected,int *halted)
{
    struct line l;int rc;
    while((rc=next(s,&l))>0) {
        if(l.kind==2) {
            if(*selected && *halted)return 0;
            *halted=l.halt;
            *selected=equal(l.section,target) || (word(l.section,"ALL") && !word(target,"KERNEL"));
        } else if(l.kind==1 && *selected && critical(l.text)) { *out=l.text;return 1; }
    }
    return rc;
}
static int compare_effective(const unsigned char *a,size_t an,const unsigned char *b,size_t bn,struct span target)
{
    struct scan sa={.p=a,.n=an},sb={.p=b,.n=bn};int as=0,ah=0,bs=0,bh=0;
    for(;;) {
        struct span x={0},y={0};int ar=effective(&sa,target,&x,&as,&ah),br=effective(&sb,target,&y,&bs,&bh);
        if(ar<0 || br<0)return VAU_INVALID;
        if(ar!=br || (ar && !equal(x,y)))return VAU_DENIED;
        if(!ar)return VAU_OK;
    }
}
int vau_tai_config_check(const void *before,size_t an,const void *after,size_t bn,
    int needs_recovery,int recovery_valid)
{
    const unsigned char *a=before,*b=after;
    if((needs_recovery!=0 && needs_recovery!=1) || (recovery_valid!=0 && recovery_valid!=1) ||
        validate(a,an) || validate(b,bn))return VAU_INVALID;
    if(needs_recovery && !recovery_valid)return VAU_DENIED;
    struct scan sa={.p=a,.n=an},sb={.p=b,.n=bn};
    for(;;) {
        struct line x={0},y={0};int ar=next_critical(&sa,&x),br=next_critical(&sb,&y);
        if(ar<0 || br<0)return VAU_INVALID;
        if(ar!=br || (ar && (!equal(x.text,y.text) || !equal(x.section,y.section) || x.halt!=y.halt)))return VAU_DENIED;
        if(!ar)break;
    }
    /* Every named context in either document plus KERNEL and the unnamed ALL
     * context. This also catches a newly inserted !ALL halting before a core
     * plugin without changing its own section or line. */
    int rc=compare_effective(a,an,b,bn,(struct span){(const unsigned char *)"KERNEL",6});
    if(rc)return rc;
    rc=compare_effective(a,an,b,bn,(struct span){NULL,0});if(rc)return rc;
    for(unsigned pass=0;pass<2;++pass) {
        struct scan s={.p=pass ? b:a,.n=pass ? bn:an};struct line l;
        while(next(&s,&l)>0)if(l.kind==2) {
            rc=compare_effective(a,an,b,bn,l.section);if(rc)return rc;
        }
    }
    return VAU_OK;
}
