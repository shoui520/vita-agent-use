/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "frames_vita.h"
#include <psp2/kernel/sysmem.h>
#include <string.h>
/* The native codec maps each buffer independently as one physical range. */
_Static_assert(VAU_FRAME_POOL_BYTES<=4u*1024u*1024u,"Bounded frame pool");
_Static_assert(!(VAU_FRAME_POOL_BYTES&4095u),"User allocation granularity");
_Static_assert(!(VAU_FRAME_RAW_BYTES&255) && !(VAU_FRAME_YUV_BYTES&255),"Codec buffer alignment");
int vau_frames_end(struct vau_frames *f)
{
    if (!f) return VAU_INVALID;
    if (f->borrowed) return VAU_BUSY;
    int rc=vau_jpeg_end(&f->encoder);
    if (rc<0) return rc;
    f->ready=0;
    while (f->allocated) {
        rc=sceKernelFreeMemBlock(f->memory_id[f->allocated-1]);
        if (rc<0) return rc;
        --f->allocated;
    }
    memset(f,0,sizeof(*f));
    return VAU_OK;
}
int vau_frames_init(struct vau_frames *f,unsigned ratio)
{
    if (!f || ratio>255) return VAU_INVALID;
    if (f->allocated || f->ready || f->encoder.ready) return VAU_BUSY;
    /* Ordinary user allocations accept page-sized buffers with PHYCONT.
     * Separate ranges avoid requiring one large contiguous physical extent.
     * Allocation is bounded and on demand, with no noncontiguous fallback. */
    const unsigned sizes[3]={VAU_FRAME_PAGE_BYTES(VAU_FRAME_RAW_BYTES),
        VAU_FRAME_PAGE_BYTES(VAU_FRAME_YUV_BYTES),VAU_FRAME_PAGE_BYTES(VAU_FRAME_JPEG_BYTES)};
    const char *names[3]={"vau-frame-raw","vau-frame-yuv","vau-frame-jpeg"};
    unsigned char **buffers[3]={&f->raw,&f->yuv,&f->jpeg};
    f->ratio=ratio;
    for (unsigned i=0;i<3;++i) {
        SceKernelAllocMemBlockOpt options={.size=sizeof(options),
            .attr=SCE_KERNEL_ALLOC_MEMBLOCK_ATTR_PHYCONT};
        SceUID uid=sceKernelAllocMemBlock(names[i],SCE_KERNEL_MEMBLOCK_TYPE_USER_MAIN_RW,
            sizes[i],&options);
        int error=uid<0 ? uid : VAU_OK;
        if (!error) {
            f->memory_id[f->allocated++]=uid;
            void *base=NULL;
            error=sceKernelGetMemBlockBase(uid,&base);
            if (!error && (!base || ((uintptr_t)base&255))) error=VAU_DEVICE_ERROR;
            if (!error) *buffers[i]=base;
        }
        if (error<0) {
            int cleanup=vau_frames_end(f);
            return cleanup<0 ? cleanup : error;
        }
    }
    f->ready=1;
    return VAU_OK;
}
static void pad_image(unsigned char *raw,unsigned width,unsigned height,unsigned pitch,unsigned rows)
{
    /* Expand in reverse order so moving rows cannot overwrite unread pixels. */
    if (pitch!=width) for(unsigned y=height;y--;) {
        unsigned char *row=raw+(size_t)y*pitch*4;
        memmove(row,raw+(size_t)y*width*4,(size_t)width*4);
        for(unsigned x=width;x<pitch;++x) memcpy(row+x*4,row+(width-1)*4,4);
    }
    for(unsigned y=height;y<rows;++y)
        memcpy(raw+(size_t)y*pitch*4,raw+(size_t)(height-1)*pitch*4,(size_t)pitch*4);
}
int vau_frames_capture(struct vau_frames *f,struct vau_frame *out)
{
    if (!out) return VAU_INVALID;
    memset(out,0,sizeof(*out));
    if (!f || !f->ready) return VAU_INVALID;
    if (f->borrowed) return VAU_BUSY;
    VauFrameInfo info={0};
    out->failure_stage=VAU_FRAME_STAGE_CAPTURE;
    int rc=vauScreenCapture(f->raw,VAU_FRAME_RAW_BYTES,&info);
    if (rc<0) return rc;
    if (info.size!=sizeof(info) || info.abi!=VAU_ABI || !info.width || info.width>960 ||
        !info.height || info.height>544 || info.pitch!=info.width || info.pixel_format!=0 ||
        info.bytes!=info.width*info.height*4) return VAU_DEVICE_ERROR;
    unsigned width=(info.width+15)&~15u,height=(info.height+15)&~15u;
    if(width<64) width=64;
    if(height<64) height=64;
    pad_image(f->raw,info.width,info.height,width,height);
    if (f->encoder.ready && (f->encoder.width!=width || f->encoder.height!=height)) {
        out->failure_stage=VAU_FRAME_STAGE_CLEANUP;
        rc=vau_jpeg_end(&f->encoder);
        if (rc<0) return rc;
    }
    if (!f->encoder.ready) {
        out->failure_stage=VAU_FRAME_STAGE_JPEG_INIT;
        rc=vau_jpeg_init(&f->encoder,width,height,f->yuv,VAU_FRAME_YUV_BYTES,
            f->jpeg,VAU_FRAME_JPEG_BYTES,f->ratio);
        if (rc<0) return rc;
    }
    out->failure_stage=VAU_FRAME_STAGE_JPEG_REGION;
    rc=vau_jpeg_region(&f->encoder,info.width,info.height);
    if (rc<0) return rc;
    size_t bytes=0;
    out->failure_stage=VAU_FRAME_STAGE_JPEG_ENCODE;
    rc=vau_jpeg_encode(&f->encoder,f->raw,VAU_FRAME_RAW_BYTES,width,&bytes);
    if (rc<0) return rc;
    out->failure_stage=VAU_FRAME_STAGE_NONE;
    out->capture=info; out->jpeg=f->jpeg; out->jpeg_bytes=bytes;
    f->borrowed=1;
    return VAU_OK;
}
void vau_frames_release(struct vau_frames *f)
{ if(f) f->borrowed=0; }
