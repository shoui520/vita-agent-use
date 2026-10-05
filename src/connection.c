/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "format.h"
#include "connection.h"
#include "json.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

static void release_frame(struct vau_connection *c)
{
    if (c->release_frame) c->release_frame(c->frame_context);
    c->release_frame=NULL; c->frame_context=NULL;
    memset(&c->frame,0,sizeof(c->frame)); c->binary_header=0;
}
const unsigned char *vau_connection_output(const struct vau_connection *c,size_t *size)
{
    if (!size) return NULL;
    *size=0;
    if (!c || c->state!=VAU_CONNECTION_WRITING || c->output_sent>=c->output_size) return NULL;
    const unsigned char *p;
    if (c->binary_header && c->output_sent>=c->binary_header) {
        size_t offset=c->output_sent-c->binary_header;
        p=c->frame.jpeg+offset; *size=c->frame.jpeg_bytes-offset;
    } else {
        p=(const unsigned char *)c->output+c->output_sent;
        *size=(c->binary_header ? c->binary_header : c->output_size)-c->output_sent;
    }
    if (*size>4096) *size=4096;
    return p;
}

void vau_connection_close(struct vau_connection *c)
{
    if (!c) return;
    release_frame(c);
    /* Erase credentials and responses, even when the socket failed midway. */
    volatile unsigned char *p=(volatile unsigned char *)c;
    for (size_t i=0;i<sizeof(*c);++i) p[i]=0;
    c->state=VAU_CONNECTION_CLOSED;
}
int vau_connection_init(struct vau_connection *c, struct vau_service *s, uint64_t now)
{
    if (!c || !s) return VAU_INVALID;
    memset(c,0,sizeof(*c));
    c->started_us=c->phase_us=c->last_us=now;
    if (vau_service_transport_poll(s)<0) {
        vau_connection_close(c);
        return VAU_DENIED;
    }
    c->generation=s->auth.stop_generation;
    return VAU_OK;
}
int vau_connection_poll(struct vau_connection *c, struct vau_service *s, uint64_t now)
{
    if (!c || !s) return VAU_INVALID;
    if (c->state==VAU_CONNECTION_CLOSED) return VAU_DENIED;
    uint64_t limit=c->state==VAU_CONNECTION_READING && !c->request.used ?
        VAU_CONNECTION_IDLE_US : VAU_CONNECTION_MESSAGE_US;
    if (now<c->last_us || now-c->started_us>=VAU_CONNECTION_LIFETIME_US ||
        now-c->phase_us>=limit || vau_service_transport_poll(s)<0 ||
        c->generation!=s->auth.stop_generation) {
        vau_connection_close(c);
        return VAU_DENIED;
    }
    c->last_us=now;
    if(c->push_response && !vau_auth_lookup(&s->auth,c->push_token,VAU_TOKEN_HEX_BYTES,now)) {
        vau_connection_close(c);return VAU_DENIED;
    }
    if (c->release_frame || c->file_response || c->audit_response) {
        struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,now);
        if (!session || !(session->rights&VAU_RIGHT_OBSERVE)) {
            vau_connection_close(c); return VAU_DENIED;
        }
    }
    if(c->upload_response) {
        struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,now);
        if(!session || !(session->rights&VAU_RIGHT_CONTROL) || !session->subject[0]) {
            vau_connection_close(c);return VAU_DENIED;
        }
    }
    return VAU_OK;
}
static int capture(struct vau_connection *c,struct vau_service *s,const struct vau_native_api *api,
    unsigned *status,char *error,size_t capacity)
{
    if (!api->clock) return VAU_INVALID;
    struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,api->clock(api->context));
    int rc=VAU_DENIED;
    *status=401;
    if (session) {
        *status=403;
        if (session->rights&VAU_RIGHT_OBSERVE) {
            *status=400; rc=VAU_INVALID;
            if (c->request.body_bytes==2 && !memcmp(c->request.data+c->request.header_bytes,"{}",2)) {
                *status=500; rc=VAU_UNSUPPORTED;
                if (api->frame && api->release_frame) {
                    rc=api->frame(api->context,&c->frame);
                    if (rc>=0) {
                        c->release_frame=api->release_frame; c->frame_context=api->context;
                        VauFrameInfo *i=&c->frame.capture;
                        if (c->frame.jpeg && c->frame.jpeg_bytes>=4 && c->frame.jpeg_bytes<=VAU_FRAME_JPEG_LIMIT &&
                            i->size==sizeof(*i) && i->abi==VAU_ABI && i->width && i->width<=960 &&
                            i->height && i->height<=544 && i->process_id>0 && i->finished_us>=i->started_us) {
                            *status=200; return 0;
                        }
                        release_frame(c); rc=VAU_DEVICE_ERROR;
                    }
                }
            }
        }
    }
    static const char *const stages[]={NULL,"pool","capture","jpeg_init","jpeg_region","jpeg_encode","cleanup"};
    unsigned stage=c->frame.failure_stage;
    const char *detail=stage==VAU_FRAME_STAGE_CAPTURE && (uint32_t)rc==UINT32_C(0x80290008) ?
        ",\"name\":\"SCE_DISPLAY_ERROR_NO_PIXEL_DATA\",\"message\":\"Cannot screenshot with no framebuffer present\"" : "";
    VauFrameInfo *observed=&c->frame.capture;
    if (stage>0 && stage<VAU_FRAME_STAGE_COUNT && observed->size==sizeof(*observed) &&
        observed->abi==VAU_ABI && observed->process_id>0)
        return vau_snprintf(error,capacity,"{\"error\":\"frame_unavailable\",\"code\":%d,\"stage\":\"%s\"%s,"
            "\"display\":{\"width\":%u,\"height\":%u,\"pitch\":%u,\"pixel_format\":%u,\"process\":%d}}",
            rc,stages[stage],detail,observed->width,observed->height,observed->pitch,
            observed->pixel_format,observed->process_id);
    if(stage>0 && stage<VAU_FRAME_STAGE_COUNT)
        return vau_snprintf(error,capacity,"{\"error\":\"frame_unavailable\",\"code\":%d,\"stage\":\"%s\"%s}",rc,stages[stage],detail);
    return vau_snprintf(error,capacity,"{\"error\":\"frame_unavailable\",\"code\":%d}",rc);
}
static int upload_file(struct vau_connection *c,struct vau_service *s,const struct vau_native_api *api,
    unsigned *status,char *output,size_t capacity)
{
    int rc=VAU_DENIED;*status=401;
    struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,api->clock(api->context));
    if(session) {
        *status=403;
        if((session->rights&VAU_RIGHT_CONTROL) && session->subject[0]) {
            struct vau_upload_message message;
            rc=vau_upload_wire_parse(c->request.data+c->request.header_bytes,c->request.body_bytes,session->subject,&message);
            *status=400;
            if(!rc) {
                struct vau_upload_status progress={0};struct vau_write_record record={0};
                rc=api->file_upload ? api->file_upload(api->context,&message,&progress,&record):VAU_UNSUPPORTED;
                /* Application errors are a completed HTTP exchange; reconnect
                 * is unnecessary and operation identity makes retries durable. */
                c->upload_open_us=progress.journal_open_us;
                c->upload_work_us=progress.work_us;c->upload_close_us=progress.journal_close_us;
                c->upload_response=1;*status=200;return vau_upload_wire_reply(&message,rc,&progress,&record,output,capacity);
            }
        }
    }
    return vau_snprintf(output,capacity,"{\"error\":\"upload_unavailable\",\"code\":%d}",rc);
}
static int read_audit(struct vau_connection *c,struct vau_service *s,const struct vau_native_api *api,
    unsigned *status,char *output,size_t capacity)
{
    int rc=VAU_DENIED;*status=401;
    struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,api->clock(api->context));
    if(session) {
        *status=403;
        if(session->rights&VAU_RIGHT_OBSERVE) {
            *status=400;rc=VAU_INVALID;
            const char *json=c->request.data+c->request.header_bytes;
            struct vau_json_token tokens[4];size_t count;char key[16],digits[21];uint64_t after;
            if(!vau_json_parse(json,c->request.body_bytes,tokens,4,&count) && count==3 &&
                tokens[0].type==VAU_JSON_OBJECT && !vau_json_ascii(json,&tokens[1],key,sizeof(key)) &&
                !strcmp(key,"after") && !vau_json_ascii(json,&tokens[2],digits,sizeof(digits)) &&
                digits[0] && !(digits[0]=='0' && digits[1])) {
                struct vau_json_token number={0,strlen(digits),0,VAU_JSON_NUMBER};
                if(!vau_json_u64(digits,&number,&after) && after<=INT64_MAX) {
                    *status=500;rc=api->audit_export ? api->audit_export(api->context,after,output,capacity):VAU_UNSUPPORTED;
                    if(rc>0 && (size_t)rc<capacity){c->audit_response=1;*status=200;return rc;}
                    if(rc>=0)rc=VAU_DEVICE_ERROR;
                }
            }
        }
    }
    return vau_snprintf(output,capacity,"{\"error\":\"audit_unavailable\",\"code\":%d}",rc);
}
static int read_file(struct vau_connection *c,struct vau_service *s,const struct vau_native_api *api,
    unsigned *status,char *output,size_t capacity)
{
    if (!api->clock) return VAU_INVALID;
    int rc=VAU_DENIED; *status=401;
    struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,api->clock(api->context));
    if (session) {
        *status=403;
        if (session->rights&VAU_RIGHT_OBSERVE) {
            *status=400; rc=VAU_INVALID;
            const char *json=c->request.data+c->request.header_bytes;
            struct vau_json_token tokens[8]; size_t count; char path[VAU_PATH_MAX];
            unsigned seen=0; uint64_t offset=0,length=0;
            if (!vau_json_parse(json,c->request.body_bytes,tokens,8,&count) && tokens[0].type==VAU_JSON_OBJECT) {
                for (size_t i=1;i<tokens[0].next;i=tokens[i+1].next) {
                    char key[16]; unsigned bit;
                    if (vau_json_ascii(json,&tokens[i],key,sizeof(key))) { seen=0; break; }
                    if (!strcmp(key,"path")) { bit=1; if (vau_json_utf8(json,&tokens[i+1],path,sizeof(path))) { seen=0; break; } }
                    else if (!strcmp(key,"offset")) {
                        char digits[21]; struct vau_json_token number={0}; bit=2;
                        if (vau_json_ascii(json,&tokens[i+1],digits,sizeof(digits)) || !digits[0] || (digits[0]=='0' && digits[1])) { seen=0; break; }
                        number.end=strlen(digits); number.type=VAU_JSON_NUMBER;
                        if (vau_json_u64(digits,&number,&offset) || offset>INT64_MAX) { seen=0; break; }
                    } else if (!strcmp(key,"length")) { bit=4; if (vau_json_u64(json,&tokens[i+1],&length) || !length || length>VAU_FILE_READ_BYTES) { seen=0; break; } }
                    else { seen=0; break; }
                    if (seen&bit) { seen=0; break; } seen|=bit;
                }
                if (seen==7) {
                    *status=500;
                    rc=vau_file_read(api->file_read,api->context,path,offset,output,(uint32_t)length,&c->file_chunk);
                    if (rc>=0) { c->file_response=1; c->file_offset=offset; *status=200; return (int)c->file_chunk.count; }
                    if (rc==VAU_DENIED) *status=403;
                }
            }
        }
    }
    return vau_snprintf(output,capacity,"{\"error\":\"file_unavailable\",\"code\":%d}",rc);
}
int vau_connection_feed(struct vau_connection *c, struct vau_service *s,
                        const struct vau_native_api *api, uint64_t now,
                        const void *bytes, size_t size)
{
    int rc=vau_connection_poll(c,s,now);
    if (rc<0) return rc;
    if (c->state!=VAU_CONNECTION_READING || !bytes || !size || !api) {
        vau_connection_close(c);
        return VAU_INVALID;
    }
    if (!c->request.used) c->phase_us=now;
    enum vau_http_state state=vau_http_feed(&c->request,bytes,size);
    if (state==VAU_HTTP_MORE) return VAU_OK;
    if (state==VAU_HTTP_ERROR) {
        vau_connection_close(c);
        return VAU_INVALID;
    }
    /* Only a framed request with a live token may wake a display. Inactive
     * transport is not permission to execute commands with an unhealthy monitor. */
    int background=!c->request.frame_request && !c->request.file_read_request &&
        !c->request.audit_request && !c->request.upload_request &&
        vau_protocol_background_request(c->request.data+c->request.header_bytes,c->request.body_bytes);
    if(!background && vau_service_poll(s)<0) {
        struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,api->clock(api->context));
        if(!session || !api->wake || api->wake(api->context)<0 || vau_service_poll(s)<0) {
            vau_connection_close(c);return VAU_DENIED;
        }
    }
    if(!background && s->activity) {
        uint64_t activity_us=api->clock(api->context);
        struct vau_session *active=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,activity_us);
        if(active && (active->rights&VAU_RIGHT_CONTROL) && active->agent_name[0])
            s->activity(s->activity_context,active->handle,active->agent_name,activity_us);
    }
    unsigned status=500;
    int body=c->request.upload_request ? upload_file(c,s,api,&status,
        c->output+VAU_CONNECTION_HEADER_BYTES,VAU_RESPONSE_BYTES) : c->request.audit_request ? read_audit(c,s,api,&status,
        c->output+VAU_CONNECTION_HEADER_BYTES,VAU_FILE_READ_BYTES) : c->request.file_read_request ? read_file(c,s,api,&status,
        c->output+VAU_CONNECTION_HEADER_BYTES,VAU_RESPONSE_BYTES) : c->request.frame_request ? capture(c,s,api,&status,
        c->output+VAU_CONNECTION_HEADER_BYTES,VAU_RESPONSE_BYTES) :
        vau_service_request(s,api,&c->request,c->output+VAU_CONNECTION_HEADER_BYTES,VAU_RESPONSE_BYTES,&status);
    /* A stop observed during dispatch closes without leaking queued output. */
    if (body<0 || (!body && !c->release_frame && !c->file_response) || (unsigned)body>((c->file_response || c->request.audit_request) ? VAU_FILE_READ_BYTES : VAU_RESPONSE_BYTES) ||
        vau_service_transport_poll(s)<0 || s->auth.stopped ||
        c->generation!=s->auth.stop_generation) {
        vau_connection_close(c);
        return VAU_DENIED;
    }
    if(!c->request.frame_request && !c->request.file_read_request && !c->request.audit_request && !c->request.upload_request && status==200) {
        struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,api->clock(api->context));
        if(session && session->reboot_reply) {
            c->reboot=api->reboot; c->reboot_context=api->context;
            c->reboot_handle=session->handle;
        }
    }
    memcpy(c->push_token,c->request.token,sizeof(c->push_token));
    ++c->requests;
    now=api->clock(api->context);
    /* An authenticated capture can legitimately have no framebuffer. Return
     * that completed error without interrupting the session's event stream. */
    c->close_after_response=c->reboot || c->request.close_connection ||
        (status!=200 && !(c->request.frame_request && status==500)) ||
        c->requests>=VAU_CONNECTION_MAX_REQUESTS;
    if (c->file_response) {
        struct vau_file_info *info=&c->file_chunk.info;
        int header=vau_snprintf(c->output,VAU_CONNECTION_HEADER_BYTES,
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n"
            "Cache-Control: no-store\r\nConnection: %s\r\nX-Vita-Offset: %" PRIu64 "\r\n"
            "X-Vita-File-Bytes: %" PRIu64 "\r\nX-Vita-Modified: %u-%u-%uT%u:%u:%u.%u\r\n\r\n",
            c->file_chunk.count,c->close_after_response ? "close" : "keep-alive",c->file_offset,c->file_chunk.file_bytes,
            info->year,info->month,info->day,info->hour,info->minute,info->second,info->microsecond);
        if (header<0 || (unsigned)header>=VAU_CONNECTION_HEADER_BYTES) { vau_connection_close(c); return VAU_DEVICE_ERROR; }
        memmove(c->output+header,c->output+VAU_CONNECTION_HEADER_BYTES,(size_t)body);
        c->output_size=(size_t)header+(size_t)body;
        c->output_sent=0; c->state=VAU_CONNECTION_WRITING; c->phase_us=now;
        return vau_connection_poll(c,s,api->clock(api->context));
    }
    if (c->release_frame) {
        VauFrameInfo *i=&c->frame.capture;
        int n=vau_snprintf(c->output,VAU_CONNECTION_HEADER_BYTES,
            "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: %zu\r\n"
            "Cache-Control: no-store\r\nConnection: %s\r\n"
            "X-Vita-Width: %u\r\nX-Vita-Height: %u\r\nX-Vita-Process: %" PRId32 "\r\n"
            "X-Vita-Capture-Start: %" PRIu64 "\r\nX-Vita-Capture-End: %" PRIu64 "\r\n\r\n",
            c->frame.jpeg_bytes,c->close_after_response ? "close" : "keep-alive",
            i->width,i->height,i->process_id,i->started_us,i->finished_us);
        if (n<0 || (unsigned)n>=VAU_CONNECTION_HEADER_BYTES) {
            vau_connection_close(c); return VAU_DEVICE_ERROR;
        }
        c->binary_header=(size_t)n; c->output_size=(size_t)n+c->frame.jpeg_bytes;
        c->output_sent=0; c->state=VAU_CONNECTION_WRITING; c->phase_us=now;
        return vau_connection_poll(c,s,api->clock(api->context));
    }
    int header=(c->request.audit_request ? vau_http_audit_response_header:vau_http_response_header_ex)(c->output,VAU_CONNECTION_HEADER_BYTES,
        status,(size_t)body,!c->close_after_response);
    if (header<0) {
        vau_connection_close(c);
        return header;
    }
    if(c->upload_response) {
        /* Optional headers preserve the JSON wire contract for old clients. */
        int extra=vau_snprintf(c->output+header-2,VAU_CONNECTION_HEADER_BYTES-(size_t)header+2,
            "X-Vita-Upload-Journal-Open-Us: %" PRIu64 "\r\n"
            "X-Vita-Upload-Work-Us: %" PRIu64 "\r\n"
            "X-Vita-Upload-Journal-Close-Us: %" PRIu64 "\r\n\r\n",
            c->upload_open_us,c->upload_work_us,c->upload_close_us);
        if(extra<0 || (size_t)extra>=VAU_CONNECTION_HEADER_BYTES-(size_t)header+2) {
            vau_connection_close(c);return VAU_DEVICE_ERROR;
        }
        header=header-2+extra;
    }
    memmove(c->output+header,c->output+VAU_CONNECTION_HEADER_BYTES,(size_t)body);
    c->output_size=(size_t)header+(size_t)body;
    c->output_sent=0;
    c->state=VAU_CONNECTION_WRITING;
    c->phase_us=now;
    return VAU_OK;
}
int vau_connection_written(struct vau_connection *c, struct vau_service *s,
                           uint64_t now, size_t size)
{
    int rc=vau_connection_poll(c,s,now);
    if (rc<0) return rc;
    if (c->state!=VAU_CONNECTION_WRITING || size>c->output_size-c->output_sent) {
        vau_connection_close(c);
        return VAU_INVALID;
    }
    c->output_sent+=size;
    if (c->output_sent==c->output_size) {
        release_frame(c);
        if(c->reboot) {
            /* Full protected reply accepted by transport. Stop/revoke control
             * and release native input before requesting the OS cold reset. */
            int (*reboot)(void *)=c->reboot; void *context=c->reboot_context;
            struct vau_session *session=vau_auth_lookup(&s->auth,c->request.token,VAU_TOKEN_HEX_BYTES,now);
            if(!session || session->handle!=c->reboot_handle || !session->reboot_pending) {
                vau_connection_close(c); return VAU_DENIED;
            }
            vau_auth_stop(&s->auth);
            int released=s->input.initialized ? vau_input_owner_poll(&s->input,&s->auth) : VAU_OK;
            vau_connection_close(c);
            return released<0 ? released : reboot(context);
        }
        if (c->close_after_response) vau_connection_close(c);
        else {
            vau_http_init(&c->request);
            memset(c->output,0,sizeof(c->output));
            c->output_size=c->output_sent=0; c->push_response=0;c->file_response=0;c->audit_response=0;c->upload_response=0;
            memset(&c->file_chunk,0,sizeof(c->file_chunk)); c->file_offset=0;
            c->state=VAU_CONNECTION_READING;
            c->phase_us=now;
        }
    }
    return VAU_OK;
}

/* A push frame is a complete HTTP response marked X-Vita-Event. It can only
 * enter the writer between replies. There is one TLS writer and no extra queue,
 * request arena, framebuffer copy, socket, or thread. Native producers stay
 * independent of this bounded 100ms drain. */
static uint32_t push_counter(const char *json,const char *key)
{
    const char *p=strstr(json,key);uint64_t n=0;if(!p)return 0;p+=strlen(key);
    while(*p>='0' && *p<='9'){n=n*10+(unsigned)(*p++-'0');if(n>UINT32_MAX)return 0;}
    return (uint32_t)n;
}
int vau_connection_push(struct vau_connection *c,struct vau_service *s,const struct vau_native_api *api,uint64_t now)
{
    if(c->state!=VAU_CONNECTION_READING || c->request.used || now<c->push_due_us)return 0;
    c->push_due_us=now+100000;
    struct vau_session *session=vau_auth_lookup(&s->auth,c->push_token,VAU_TOKEN_HEX_BYTES,now);
    if(!session || !session->push_enabled || !(session->rights&VAU_RIGHT_OBSERVE))return 0;
    unsigned slot=c->push_slot++%12; /* Dumps every 200ms, round-robin others. */
    char *body=c->output+VAU_CONNECTION_HEADER_BYTES;
    const char *kind;int n=VAU_UNSUPPORTED;
    if(!(slot&1)) {
        kind="coredump.batch";
        if(api->events)n=api->events(api->context,1,session->dump_after,body,VAU_FILE_READ_BYTES);
        if(n>=0){uint32_t dropped=push_counter(body,"\"dropped\":");unsigned changed=dropped!=session->dump_dropped;session->dump_dropped=dropped;
            session->dump_after=push_counter(body,"\"next\":");if(strstr(body,"\"events\":[]") && !push_counter(body,"\"lost\":") && !changed)return 0;}
    } else if(slot==1) {
        kind="dialog.batch";
        if(api->dialog_events)n=api->dialog_events(api->context,1,session->dialog_after,body,VAU_FILE_READ_BYTES);
        if(n>=0){uint32_t dropped=push_counter(body,"\"dropped\":");unsigned changed=dropped!=session->dialog_dropped;session->dialog_dropped=dropped;
            session->dialog_after=push_counter(body,"\"next\":");if(strstr(body,"\"events\":[]") && !push_counter(body,"\"lost\":") && !changed)return 0;}
    } else if(slot==3) {
        kind="performance.batch";
        if(session->perf_push && api->performance)n=api->performance(api->context,session->handle,2,0,session->perf_after,body,VAU_FILE_READ_BYTES);
        if(n>=0){session->perf_after=push_counter(body,"\"next_after\":");if(strstr(body,"\"samples\":[]"))return 0;}
    } else {
        kind="log.batch";unsigned index=(slot-5)/2;
        if(index<4 && session->log_ids[index] && api->log_watch)n=api->log_watch(api->context,session->subject,1,NULL,NULL,session->log_ids[index],body,VAU_FILE_READ_BYTES);
        if(n>=0 && strstr(body,"\"data\":\"\"") && strstr(body,"\"reset\":false"))return 0;
    }
    if(n<0 || n>=(int)VAU_FILE_READ_BYTES){c->push_burst=0;return 0;}
    /* Catch up an active log in bounded bursts rather than 768 bytes per
     * round. Yield after 16 frames to read pending commands and other sources. */
    if(slot>=5 && (slot&1) && strstr(body,"\"more\":true") && c->push_burst<15) {
        c->push_slot--;c->push_due_us=now+1000;c->push_burst++;
    } else c->push_burst=0;
    /* Body is formatted in-place; envelope metadata travels in bounded headers. */
    int header=vau_snprintf(c->output,VAU_CONNECTION_HEADER_BYTES,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nX-Vita-Event: %s\r\nX-Vita-Run: %s\r\nConnection: keep-alive\r\n\r\n",n,kind,session->run_id);
    if(header<0 || header>=(int)VAU_CONNECTION_HEADER_BYTES)return VAU_DEVICE_ERROR;
    memmove(c->output+header,body,(size_t)n);c->output_size=(size_t)header+(size_t)n;c->output_sent=0;
    c->state=VAU_CONNECTION_WRITING;c->phase_us=now;c->close_after_response=0;c->push_response=1;
    return 1;
}
