/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_SHELL_JPEG_H
#define VAU_SHELL_JPEG_H
#include <stddef.h>
#include <stdint.h>
/* SceShell's PS+START JPEG encoder, with an in-memory output stream. */
int vau_shell_capture_buffer(void **pixels,size_t *capacity);
int vau_shell_jpeg(const void *pixels,unsigned width,unsigned height,unsigned pitch,
    void *output,size_t capacity,unsigned ratio,size_t *bytes);
#endif
