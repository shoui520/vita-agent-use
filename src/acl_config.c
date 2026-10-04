/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "acl_config.h"
#include "json.h"
#include "vita_agent.h"
#include <string.h>
int vau_acl_config_parse(const char *json,size_t length,enum vau_tai_location tai,struct vau_file_policy *out)
{
    if(!json || !out || length>VAU_ACL_CONFIG_BYTES)return VAU_INVALID;
    struct vau_json_token t[VAU_ACL_RULES_MAX*12+8];size_t count;
    struct vau_file_policy policy={.active_tai=tai};
    if(vau_json_parse(json,length,t,sizeof(t)/sizeof(*t),&count) || t[0].type!=VAU_JSON_OBJECT)return VAU_INVALID;
    unsigned seen=0;
    for(size_t i=1;i<t[0].next;i=t[i+1].next) {
        char key[16];unsigned bit;if(vau_json_ascii(json,&t[i],key,sizeof(key)))return VAU_INVALID;
        if(!strcmp(key,"v")) {
            uint64_t v;bit=1;if(vau_json_u64(json,&t[i+1],&v) || v!=1)return VAU_INVALID;
        } else if(!strcmp(key,"rules")) {
            bit=2;if(t[i+1].type!=VAU_JSON_ARRAY)return VAU_INVALID;
            for(size_t entry=i+2;entry<t[i+1].next;entry=t[entry].next) {
                if(policy.count==VAU_ACL_RULES_MAX || t[entry].type!=VAU_JSON_OBJECT)return VAU_INVALID;
                struct vau_acl_rule *rule=&policy.rules[policy.count++];unsigned fields=0;
                for(size_t j=entry+1;j<t[entry].next;j=t[j+1].next) {
                    unsigned field;if(vau_json_ascii(json,&t[j],key,sizeof(key)))return VAU_INVALID;
                    if(!strcmp(key,"subject")) {field=1;if(vau_json_ascii(json,&t[j+1],rule->subject,sizeof(rule->subject)))return VAU_INVALID;}
                    else if(!strcmp(key,"path")) {
                        char path[VAU_PATH_MAX];field=2;
                        if(vau_json_utf8(json,&t[j+1],path,sizeof(path)) || vau_path_normalize(path,rule->path,sizeof(rule->path)))return VAU_INVALID;
                    } else if(!strcmp(key,"allow") || !strcmp(key,"deny")) {
                        uint64_t rights;field=!strcmp(key,"allow") ? 4:8;
                        if(vau_json_u64(json,&t[j+1],&rights) || rights>VAU_ACL_ALL)return VAU_INVALID;
                        if(field==4)rule->allow=(unsigned)rights;else rule->deny=(unsigned)rights;
                    } else return VAU_INVALID;
                    if(fields&field)return VAU_INVALID;
                    fields|=field;
                }
                if(fields!=15)return VAU_INVALID;
            }
        } else return VAU_INVALID;
        if(seen&bit)return VAU_INVALID;
        seen|=bit;
    }
    if(seen!=3 || vau_policy_validate(&policy))return VAU_INVALID;
    *out=policy;return VAU_OK;
}

#include "format.h"
int vau_acl_grant_prepare(const struct vau_file_policy *old,const char *subject,
    const char *path,int directory,struct vau_file_policy *out)
{
    if(!old || !subject || !out || vau_policy_validate(old))return VAU_INVALID;
    char normalized[VAU_PATH_MAX];
    if(vau_path_normalize(path,normalized,sizeof(normalized)))return VAU_INVALID;
    const char *base=strrchr(normalized,'/');base=base ? base+1:strchr(normalized,':')+1;
    if(vau_policy_core_plugin(base))return VAU_DENIED;
    struct vau_file_policy candidate=*old;unsigned i;
    for(i=0;i<candidate.count;++i)
        if(!strcmp(candidate.rules[i].subject,subject) && !strcmp(candidate.rules[i].path,normalized))break;
    if(i==candidate.count) {
        if(i==VAU_ACL_RULES_MAX)return VAU_BUSY;
        ++candidate.count;memset(&candidate.rules[i],0,sizeof(candidate.rules[i]));
        if(strlen(subject)!=64)return VAU_INVALID;
        strcpy(candidate.rules[i].subject,subject);strcpy(candidate.rules[i].path,normalized);
    }
    candidate.rules[i].allow|=VAU_ACL_WRITE;
    if(vau_policy_validate(&candidate))return VAU_INVALID;
    char probe[VAU_PATH_MAX];size_t probe_length=strlen(normalized);memcpy(probe,normalized,probe_length+1);
    /* Granting a tai subtree never grants modification of its directory root. */
    int root=!strcmp(probe,"ur0:tai") || !strcmp(probe,"ux0:tai") || !strcmp(probe,"uma0:tai");
    if(root && directory) {
        if(probe_length+sizeof("/__acl_scope_probe__")>sizeof(probe))return VAU_INVALID;
        memcpy(probe+probe_length,"/__acl_scope_probe__",sizeof("/__acl_scope_probe__"));
    }
    if(vau_policy_evaluate(&candidate,subject,VAU_FS_WRITE,probe,1)!=VAU_POLICY_ALLOW)return VAU_DENIED;
    *out=candidate;return VAU_OK;
}
int vau_acl_config_format(const struct vau_file_policy *policy,char *out,size_t capacity)
{
    if(!out || vau_policy_validate(policy))return VAU_INVALID;
    int n=vau_snprintf(out,capacity,"{\"v\":1,\"rules\":[");
    if(n<0 || (size_t)n>=capacity)return VAU_INVALID;
    size_t used=(size_t)n;
    for(unsigned i=0;i<policy->count;++i) {
        char path[VAU_PATH_MAX*6+3];const struct vau_acl_rule *r=&policy->rules[i];
        if(vau_json_quote(r->path,path,sizeof(path))<0)return VAU_INVALID;
        n=vau_snprintf(out+used,capacity-used,"%s{\"subject\":\"%s\",\"path\":%s,\"allow\":%u,\"deny\":%u}",
            i ? ",":"",r->subject,path,r->allow,r->deny);
        if(n<0 || (size_t)n>=capacity-used)return VAU_INVALID;
        used+=(size_t)n;
    }
    n=vau_snprintf(out+used,capacity-used,"]}\n");
    return n<0 || (size_t)n>=capacity-used ? VAU_INVALID:(int)(used+(size_t)n);
}
