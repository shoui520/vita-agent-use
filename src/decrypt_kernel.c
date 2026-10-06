/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Native authentication contexts adapted from TeamFAPS FAGDec (GPL-3.0).
 * No hooks, firmware patches, allocation or authentication at plugin startup.
 */
#include "decrypt.h"
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/io/fcntl.h>
#include <psp2kern/npdrm.h>
#include <taihen.h>
#include <stdatomic.h>
#include <string.h>

extern int module_get_export_func(SceUID, const char *, uint32_t, uint32_t, uintptr_t *);

static const unsigned char kernel_context[0x130] = {
	[0x008] = 0x01, [0x00e] = 0x08, [0x00f] = 0x28, [0x018] = 0x80, [0x01c] = 0xc0, [0x01e] = 0xf0,
	[0x024] = 0xff, [0x025] = 0xff, [0x026] = 0xff, [0x027] = 0xff, [0x038] = 0x80, [0x039] = 0x09,
	[0x03a] = 0x80, [0x03b] = 0x03, [0x03d] = 0x30, [0x03e] = 0x0c, [0x042] = 0x80, [0x043] = 0x09,
	[0x044] = 0x80, [0x054] = 0xff, [0x055] = 0xff, [0x056] = 0xff, [0x057] = 0xff,
};

static const unsigned char shell_context[0x130] = {
	[0x004] = 0x01, [0x006] = 0x01, [0x008] = 0x01, [0x00f] = 0x28, [0x018] = 0x40, [0x01c] = 0xc0,
	[0x01e] = 0xf0, [0x024] = 0xff, [0x025] = 0xff, [0x026] = 0xff, [0x027] = 0xff, [0x028] = 0xe0,
	[0x038] = 0x80, [0x039] = 0x09, [0x03a] = 0x80, [0x03b] = 0x07, [0x03e] = 0xc3, [0x042] = 0x20,
	[0x043] = 0x09, [0x044] = 0x40, [0x054] = 0xff, [0x055] = 0xff, [0x056] = 0xff, [0x057] = 0xff,
	[0x088] = 0x10, [0x118] = 0x10,
};

static int (*sm_start)(int *);
static int (*sm_finish)(int);
static int (*auth_header)(int, void *, int, void *);
static int (*load_segment)(int, int);
static int (*load_block)(int, void *, int);
static int (*path_id)(SceUID, const char *, int, int *);
static atomic_flag guard = ATOMIC_FLAG_INIT;
static SceUID block = -1, owner = -1;
static unsigned char *buffer;
static int ctx = -1;

static int bind(void)
{
	static const uint32_t nids[] = { 0xa9cd2a09, 0x026acbad, 0xf3411881, 0x89ccda2c, 0xbc422443 };
	uintptr_t functions[5], path = 0;

	for (unsigned i = 0; i < 5; i++) {
		int rc = module_get_export_func(KERNEL_PID, "SceSblAuthMgr", 0x7abf5135, nids[i],
		                                &functions[i]);

		if (rc < 0 || !functions[i])
			return rc < 0 ? rc : VAU_UNSUPPORTED;
	}
	int rc = module_get_export_func(KERNEL_PID, "SceIofilemgr", 0x40fd29c7, 0x9c220246, &path);

	if (rc < 0 || !path)
		return rc < 0 ? rc : VAU_UNSUPPORTED;

	sm_start     = (void *)functions[0];
	sm_finish    = (void *)functions[1];
	auth_header  = (void *)functions[2];
	load_segment = (void *)functions[3];
	load_block   = (void *)functions[4];
	path_id      = (void *)path;
	return 0;
}

static int finish(void)
{
	int rc = ctx >= 0 ? sm_finish(ctx) : 0;

	ctx   = -1;
	owner = -1;
	if (block >= 0) {
		memset(buffer, 0, VAU_DECRYPT_BLOCK);
		int freed = ksceKernelFreeMemBlock(block);

		if (rc >= 0 && freed < 0)
			rc = freed;
		block  = -1;
		buffer = NULL;
	}
	return rc;
}

static int open_self(const VauDecryptRequest *r, void *user)
{
	unsigned char context[0x130] __attribute__((aligned(64)));
	SceNpDrmLicense rif __attribute__((aligned(64)));
	int native_path = -1;
	int rc          = bind();

	if (rc < 0)
		return rc;

	block = ksceKernelAllocMemBlock("vau-self-block", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
	                                VAU_DECRYPT_BLOCK, NULL);
	if (block < 0)
		return block;
	if ((rc = ksceKernelGetMemBlockBase(block, (void **)&buffer)) < 0) {
		ksceKernelFreeMemBlock(block);
		block = -1;
		return rc;
	}
	owner = ksceKernelGetThreadId();
	rc    = ksceKernelCopyFromUser(buffer, user, r->length);
	if (rc < 0)
		goto fail;

	memcpy(context, r->rif[0] ? shell_context : kernel_context, sizeof(context));
	if (!r->rif[0])
		memcpy(context + 4, &r->self_type, 4);

	if (r->rif[0]) {
		SceUID fd = ksceIoOpen(r->rif, SCE_O_RDONLY, 0);

		if (fd < 0) {
			rc = fd;
			goto fail;
		}
		rc = ksceIoRead(fd, &rif, sizeof(rif));
		ksceIoClose(fd);
		if (rc != sizeof(rif)) {
			rc = rc < 0 ? rc : VAU_DEVICE_ERROR;
			goto fail;
		}
		rc = ksceNpDrmGetRifVitaKey(&rif, context + 0xf8, NULL, NULL, NULL, NULL);
		memset(&rif, 0, sizeof(rif));
		if (rc < 0)
			goto fail;
	}

	rc = path_id(ksceKernelGetProcessId(), r->path, 1, &native_path);
	if (rc >= 0) {
		memcpy(context + 0x128, &native_path, 4);
		rc = sm_start(&ctx);
	}
	if (rc >= 0)
		rc = auth_header(ctx, buffer, r->length, context);
	memset(context, 0, sizeof(context));
	if (rc >= 0)
		return 0;
fail:
	memset(&rif, 0, sizeof(rif));
	memset(context, 0, sizeof(context));
	finish();
	return rc;
}

int vau_decrypt_kernel(const VauDecryptRequest *r, void *user)
{
	if (!r || r->size != sizeof(*r) || r->operation > VAU_DECRYPT_FINISH ||
	    !memchr(r->path, 0, sizeof(r->path)) || !memchr(r->rif, 0, sizeof(r->rif)))
		return VAU_INVALID;
	if (atomic_flag_test_and_set_explicit(&guard, memory_order_acquire))
		return VAU_BUSY;

	int rc = VAU_INVALID;

	if (r->operation == VAU_DECRYPT_OPEN) {
		if (owner >= 0)
			rc = VAU_BUSY;
		else if (user && r->length >= 128 && r->length <= VAU_DECRYPT_HEADER && r->self_type <= 1)
			rc = open_self(r, user);
	} else if (owner != ksceKernelGetThreadId()) {
		rc = VAU_DENIED;
	} else if (r->operation == VAU_DECRYPT_FINISH) {
		rc = finish();
	} else if (r->operation == VAU_DECRYPT_SEGMENT && r->segment < VAU_DECRYPT_SEGMENTS) {
		/* Verified 3.65 export takes only context and segment index. FAGDec's
		 * extra full-segment output allocation is not used by this firmware. */
		rc = load_segment(ctx, r->segment);
	} else if (r->operation == VAU_DECRYPT_BLOCK_OP && user && r->length &&
	           r->length <= VAU_DECRYPT_BLOCK) {
		memset(buffer, 0, VAU_DECRYPT_BLOCK);
		rc = ksceKernelCopyFromUser(buffer, user, r->length);
		if (rc >= 0)
			rc = load_block(ctx, buffer, r->length);
		if (rc >= 0)
			rc = ksceKernelCopyToUser(user, buffer, r->length);
	}

	if (r->operation != VAU_DECRYPT_BLOCK_OP || rc < 0)
		ksceDebugPrintf("vau-decrypt op=%u segment=%u ctx=%d rc=%08x\n", r->operation, r->segment,
		                ctx, rc);
	atomic_flag_clear_explicit(&guard, memory_order_release);
	return rc;
}
