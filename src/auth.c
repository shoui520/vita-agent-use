/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "format.h"
#include "auth.h"
#include <string.h>
#include <stdio.h>

static void wipe(void *data, size_t size)
{
    volatile unsigned char *p=data;
    while (size--) *p++=0;
}
void vau_auth_init(struct vau_auth *a)
{
    wipe(a,sizeof(*a));
    a->next_handle=1;
}
static void reap(struct vau_auth *a, uint64_t now)
{
    for (unsigned i=0;i<VAU_AUTH_SLOTS;++i)
        if (a->entries[i].handle && now>=a->entries[i].expires_us)
            wipe(&a->entries[i],sizeof(a->entries[i]));
}
/* No early exit on differing secret bytes. Hex decoding happens separately. */
static int same(const unsigned char *a, const unsigned char *b)
{
    volatile unsigned difference=0;
    for (unsigned i=0;i<VAU_AUTH_TOKEN_BYTES;++i) difference|=a[i]^b[i];
    return difference==0;
}
int vau_auth_grant(struct vau_auth *a, unsigned rights, uint64_t now, uint64_t lifetime,
                   vau_entropy entropy, void *context, uint64_t *handle, char token[VAU_TOKEN_HEX_BYTES+1])
{
    if (!a || !entropy || !handle || !token) return VAU_INVALID;
    *handle=0; wipe(token,VAU_TOKEN_HEX_BYTES+1);
    if (a->stopped) return VAU_DENIED;
    if (!rights || (rights&~(VAU_RIGHT_OBSERVE|VAU_RIGHT_CONTROL)) || !lifetime ||
        lifetime>VAU_AUTH_MAX_LIFETIME_US || now>UINT64_MAX-lifetime || !a->next_handle)
        return VAU_INVALID;
    reap(a,now);
    unsigned slot;
    for (slot=0;slot<VAU_AUTH_SLOTS;++slot) if (!a->entries[slot].handle) break;
    if (slot==VAU_AUTH_SLOTS) return VAU_BUSY;
    unsigned char random[VAU_AUTH_TOKEN_BYTES]={0};
    int rc=entropy(context,random,sizeof(random));
    if (rc!=0) { wipe(random,sizeof(random)); return rc<0 ? rc : VAU_DEVICE_ERROR; }
    unsigned nonzero=0;
    for (unsigned i=0;i<sizeof(random);++i) nonzero|=random[i];
    if (!nonzero) { wipe(random,sizeof(random)); return VAU_DEVICE_ERROR; }
    for (unsigned i=0;i<VAU_AUTH_SLOTS;++i)
        if (a->entries[i].handle && same(a->entries[i].token,random)) {
            wipe(random,sizeof(random)); return VAU_DEVICE_ERROR;
        }
    struct vau_auth_entry *entry=&a->entries[slot];
    entry->handle=a->next_handle++;
    entry->expires_us=now+lifetime;
    memcpy(entry->token,random,sizeof(random));
    vau_session_init(&entry->session,rights);
    entry->session.handle=entry->handle;
    const char *hex="0123456789abcdef";
    for (unsigned i=0;i<sizeof(random);++i) {
        token[2*i]=hex[random[i]>>4]; token[2*i+1]=hex[random[i]&15];
    }
    token[VAU_TOKEN_HEX_BYTES]=0;
    *handle=entry->handle;
    wipe(random,sizeof(random));
    return VAU_OK;
}
int vau_auth_revoke(struct vau_auth *a, uint64_t handle)
{
    if (!a || !handle) return VAU_INVALID;
    for (unsigned i=0;i<VAU_AUTH_SLOTS;++i)
        if (a->entries[i].handle==handle) {
            wipe(&a->entries[i],sizeof(a->entries[i]));
            return VAU_OK;
        }
    return VAU_STALE;
}
void vau_auth_revoke_all(struct vau_auth *a)
{
    /* Keep the handle counter so stale UI references cannot revoke new grants. */
    wipe(a->entries,sizeof(a->entries));
}
struct vau_session *vau_auth_lookup(struct vau_auth *a, const char *token, size_t length, uint64_t now)
{
    if (!a || a->stopped || !token || length!=VAU_TOKEN_HEX_BYTES) return NULL;
    unsigned char decoded[VAU_AUTH_TOKEN_BYTES]={0};
    for (unsigned i=0;i<length;++i) {
        unsigned c=(unsigned char)token[i],n;
        if (c>='0' && c<='9') n=c-'0';
        else if (c>='a' && c<='f') n=c-'a'+10;
        else { wipe(decoded,sizeof(decoded)); return NULL; }
        decoded[i/2]=(unsigned char)((decoded[i/2]<<4)|n);
    }
    reap(a,now);
    struct vau_session *found=NULL;
    for (unsigned i=0;i<VAU_AUTH_SLOTS;++i) {
        int match=same(a->entries[i].token,decoded);
        if (match && a->entries[i].handle) found=&a->entries[i].session;
    }
    wipe(decoded,sizeof(decoded));
    return found;
}
void vau_auth_stop(struct vau_auth *a)
{
    a->stopped=1;
    if (a->stop_generation<UINT64_MAX) ++a->stop_generation;
    vau_auth_revoke_all(a);
}
int vau_auth_rearm(struct vau_auth *a, uint64_t generation)
{
    if (!a) return VAU_INVALID;
    if (!a->stopped || !generation || generation!=a->stop_generation) return VAU_STALE;
    if (generation==UINT64_MAX) return VAU_DENIED;
    a->stopped=0;
    return VAU_OK;
}
int vau_authenticated_request(struct vau_auth *a, const struct vau_native_api *api,
                               const struct vau_http_request *r, char *out, size_t cap,
                               unsigned *status)
{
    if (!a || !api || !api->clock || !r || !out || cap<VAU_RESPONSE_BYTES || !status)
        return VAU_INVALID;
    if (r->state!=VAU_HTTP_READY || r->pairing_only || r->frame_request || r->file_read_request || r->audit_request || r->upload_request) {
        *status=r->state==VAU_HTTP_ERROR ? r->error_status : 400;
        return vau_snprintf(out,cap,"{\"error\":\"invalid_http_request\"}");
    }
    struct vau_session *session=vau_auth_lookup(a,r->token,VAU_TOKEN_HEX_BYTES,api->clock(api->context));
    if (!session) {
        *status=401;
        return vau_snprintf(out,cap,"{\"error\":\"unauthorized\"}");
    }
    *status=200;
    return vau_protocol_request(session,api,r->data+r->header_bytes,r->body_bytes,out,cap);
}
