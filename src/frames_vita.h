/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_FRAMES_VITA_H
#define VAU_FRAMES_VITA_H
#include "jpeg_vita.h"
#include "frame.h"
#define VAU_FRAME_RAW_BYTES (960u*544u*4u)
#define VAU_FRAME_YUV_BYTES (960u*544u*3u/2u)
#define VAU_FRAME_JPEG_BYTES (1024u*1024u)
/* Exact PS+START JPEG size bound, Shell 3.65 function 0x366206. */
#define VAU_SHELL_JPEG_BYTES VAU_FRAME_JPEG_LIMIT
#define VAU_FRAME_PAGE_BYTES(n) (((n)+4095u)&~4095u)
#define VAU_FRAME_POOL_BYTES (VAU_FRAME_PAGE_BYTES(VAU_FRAME_RAW_BYTES)+VAU_FRAME_PAGE_BYTES(VAU_FRAME_YUV_BYTES)+VAU_FRAME_PAGE_BYTES(VAU_FRAME_JPEG_BYTES))
struct vau_frames {
    struct vau_jpeg_encoder encoder;
    int32_t memory_id[3];
    unsigned char *raw,*yuv,*jpeg;
    unsigned allocated,ready,borrowed,ratio;
};
/* Zero-initialize. One serialized user worker owns these buffers and native codec.
 * Allocation is on demand, never at module startup. The Shell software encoder
 * allocates its bounded working heap for each frame.
 * Returned bytes stay valid until release; do not capture/destroy while borrowed.
 * Caller checks authorization/stop before capture and before sending bytes. */
int vau_frames_init(struct vau_frames *frames,unsigned native_ratio);
int vau_frames_capture(struct vau_frames *frames,struct vau_frame *out);
void vau_frames_release(struct vau_frames *frames);
int vau_frames_end(struct vau_frames *frames);
#endif
