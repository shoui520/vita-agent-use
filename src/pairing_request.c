/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "pairing_request.h"
#include "json.h"
#include "vita_agent.h"
#include <string.h>
int vau_pairing_request_decode(const struct vau_http_request *http,
    struct vau_pairing_request *out)
{
    struct vau_json_token tokens[8];
    struct vau_pairing_request decoded={0};
    size_t count=0;
    unsigned seen=0;
    if (!out) return VAU_INVALID;
    memset(out,0,sizeof(*out));
    if (!http || !http->pairing_only || http->state!=VAU_HTTP_READY ||
        !http->close_connection || http->frame_request || http->file_read_request ||
        http->token[0] || http->body_bytes>VAU_PAIRING_REQUEST_BYTES ||
        http->header_bytes>VAU_HTTP_HEADER_BYTES ||
        http->used!=http->header_bytes+http->body_bytes) return VAU_INVALID;
    const char *json=http->data+http->header_bytes;
    if (vau_json_parse(json,http->body_bytes,tokens,8,&count) || !count ||
        tokens[0].type!=VAU_JSON_OBJECT) return VAU_INVALID;
    for (size_t i=1;i<tokens[0].next;) {
        char key[16];
        size_t value=i+1;
        if (value>=count || vau_json_ascii(json,&tokens[i],key,sizeof(key))) return VAU_INVALID;
        unsigned bit;
        if (!strcmp(key,"v")) {
            uint64_t version;
            bit=1;
            if (vau_json_u64(json,&tokens[value],&version) || version!=1) return VAU_INVALID;
        } else if (!strcmp(key,"agent_name")) {
            bit=2;
            if (vau_json_utf8(json,&tokens[value],decoded.name,sizeof(decoded.name))) return VAU_INVALID;
            decoded.name_length=strlen(decoded.name);
            uint16_t units[VAU_AGENT_NAME_BYTES]; size_t units_count;
            if (vau_agent_name_utf16(units,&units_count,decoded.name,decoded.name_length)) return VAU_INVALID;
        } else return VAU_INVALID;
        if (seen&bit) return VAU_INVALID;
        seen|=bit;
        i=tokens[value].next;
    }
    if (seen!=3) return VAU_INVALID;
    *out=decoded;
    return VAU_OK;
}
