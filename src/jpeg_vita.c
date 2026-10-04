/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "jpeg_vita.h"
#include <psp2/jpegenc.h>
#include <string.h>
#include <limits.h>
static int overlaps(uintptr_t a,size_t an,uintptr_t b,size_t bn)
{ return a>UINTPTR_MAX-an || b>UINTPTR_MAX-bn || (a<b+bn && b<a+an); }
int vau_jpeg_region(struct vau_jpeg_encoder *e,unsigned width,unsigned height)
{
    if (!e || !e->ready || !width || !height || width>e->width || height>e->height)
        return VAU_INVALID;
    return sceJpegEncoderSetValidRegion(e->context,(int)width,(int)height);
}
int vau_jpeg_end(struct vau_jpeg_encoder *e)
{
    if (!e) return VAU_INVALID;
    int rc=e->ready ? sceJpegEncoderEnd(e->context) : 0;
    if (rc<0) return rc; /* Owner must retain buffers if native cleanup fails. */
    memset(e,0,sizeof(*e));
    return VAU_OK;
}
int vau_jpeg_init(struct vau_jpeg_encoder *e,unsigned width,unsigned height,
    void *yuv,size_t yuv_bytes,void *output,size_t output_capacity,unsigned ratio)
{
    if (!e) return VAU_INVALID;
    if (e->ready) return VAU_BUSY;
    if (!yuv || !output || ((uintptr_t)yuv&255) || ((uintptr_t)output&255) ||
        width<64 || width>960 || height<64 || height>544 || ((width|height)&15) ||
        ratio>255 || output_capacity<256 || output_capacity>INT_MAX || (output_capacity&255))
        return VAU_INVALID;
    size_t needed=(size_t)width*height+2*((width/2+15)&~15u)*(height/2);
    if (yuv_bytes<needed || overlaps((uintptr_t)yuv,yuv_bytes,(uintptr_t)output,output_capacity) ||
        overlaps((uintptr_t)e,sizeof(*e),(uintptr_t)yuv,yuv_bytes) ||
        overlaps((uintptr_t)e,sizeof(*e),(uintptr_t)output,output_capacity)) return VAU_INVALID;
    int size=sceJpegEncoderGetContextSize();
    if (size<0) return size;
    if ((size_t)size!=sizeof(e->context)) return VAU_UNSUPPORTED;
    memset(e,0,sizeof(*e));
    SceJpegEncoderInitParam p={sizeof(p),(int)width,(int)height,
        SCE_JPEGENC_PIXELFORMAT_YCBCR420|SCE_JPEGENC_PIXELFORMAT_CSC_ARGB_YCBCR,
        output,(SceSize)output_capacity,SCE_JPEGENC_INIT_PARAM_OPTION_LPDDR2_MEMORY};
    int rc=sceJpegEncoderInitWithParam(e->context,&p);
    if (rc<0) { memset(e,0,sizeof(*e)); return rc; }
    e->ready=1; e->width=width; e->height=height;
    e->yuv=yuv; e->yuv_bytes=yuv_bytes; e->output=output; e->output_capacity=output_capacity;
    rc=sceJpegEncoderSetCompressionRatio(e->context,(int)ratio);
    if (rc<0) { (void)vau_jpeg_end(e); return rc; }
    return VAU_OK;
}
int vau_jpeg_encode(struct vau_jpeg_encoder *e,const void *argb,size_t argb_bytes,
    unsigned pitch,size_t *jpeg_bytes)
{
    if (!jpeg_bytes) return VAU_INVALID;
    *jpeg_bytes=0;
    if (!e || !e->ready || !argb || ((uintptr_t)argb&15) || pitch<e->width ||
        pitch>2032 || (pitch&3)) return VAU_INVALID;
    size_t bytes=(size_t)pitch*e->height*4;
    if (argb_bytes<bytes || overlaps((uintptr_t)argb,bytes,(uintptr_t)e,sizeof(*e)) ||
        overlaps((uintptr_t)argb,bytes,(uintptr_t)e->yuv,e->yuv_bytes) ||
        overlaps((uintptr_t)argb,bytes,(uintptr_t)e->output,e->output_capacity)) return VAU_INVALID;
    int rc=sceJpegEncoderSetOutputAddr(e->context,e->output,(SceSize)e->output_capacity);
    if (rc<0) return rc;
    rc=sceJpegEncoderCsc(e->context,e->yuv,argb,(int)pitch,SCE_JPEGENC_PIXELFORMAT_ARGB8888);
    if (rc<0) return rc;
    rc=sceJpegEncoderEncode(e->context,e->yuv);
    if (rc<0) return rc;
    if (rc<4 || (size_t)rc>e->output_capacity) return VAU_DEVICE_ERROR;
    *jpeg_bytes=(size_t)rc;
    return VAU_OK;
}
