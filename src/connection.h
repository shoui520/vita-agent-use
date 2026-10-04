/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_CONNECTION_H
#define VAU_CONNECTION_H
#include "service.h"
#define VAU_CONNECTION_IDLE_US UINT64_C(1800000000)
#define VAU_CONNECTION_MESSAGE_US UINT64_C(5000000)
#define VAU_CONNECTION_LIFETIME_US UINT64_C(3600000000)
#define VAU_CONNECTION_MAX_REQUESTS 65536u
#define VAU_CONNECTION_HEADER_BYTES 512u
enum vau_connection_state { VAU_CONNECTION_READING, VAU_CONNECTION_WRITING, VAU_CONNECTION_CLOSED };
struct vau_connection {
    struct vau_http_request request;
    char output[VAU_CONNECTION_HEADER_BYTES+VAU_FILE_READ_BYTES];
    size_t output_size,output_sent,binary_header;
    struct vau_frame frame;
    void (*release_frame)(void *);
    void *frame_context;
    uint64_t started_us,phase_us,last_us,generation;
    unsigned requests,close_after_response,file_response,audit_response,upload_response;
    uint64_t file_offset,push_due_us;
    char push_token[65];
    unsigned push_slot,push_response,push_burst;
    int (*reboot)(void *);
    void *reboot_context;
    uint64_t reboot_handle;
    struct vau_file_chunk file_chunk;
    enum vau_connection_state state;
};
/* Established protected transport only. Serialize all calls with the service.
 * Poll while idle/awaiting I/O at most 16 ms apart; close TLS/socket on CLOSED.
 * Pairing uses a separate local approval path. */
int vau_connection_init(struct vau_connection *,struct vau_service *,uint64_t);
int vau_connection_poll(struct vau_connection *,struct vau_service *,uint64_t);
int vau_connection_feed(struct vau_connection *,struct vau_service *,const struct vau_native_api *,
    uint64_t,const void *,size_t);
/* Segments at most 4096 bytes; pointer/size stable across retryable TLS writes.
 * Advance only accepted bytes. No next request before response completion.
 * JPEG borrows the capture pool; file chunks use bounded connection storage. */
int vau_connection_written(struct vau_connection *,struct vau_service *,uint64_t,size_t);
const unsigned char *vau_connection_output(const struct vau_connection *,size_t *);
int vau_connection_push(struct vau_connection *,struct vau_service *,const struct vau_native_api *,uint64_t);
void vau_connection_close(struct vau_connection *);
#endif
