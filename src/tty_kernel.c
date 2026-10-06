/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Native debug callback ABI/NIDs researched from CatLog (Cat, 2024) and
 * PrincessLog (Princess of Sleeping and Asakura Reiko, 2020).
 */

#include "tty_ring.h"
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <taihen.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static struct vau_tty_ring ring;
static atomic_flag busy = ATOMIC_FLAG_INIT, installing = ATOMIC_FLAG_INIT;
static _Atomic uint32_t enabled, dropped, kernel_calls, kernel_threads[4];
static tai_hook_ref_t refs[4];
static int ids[4] = { -1, -1, -1, -1 };
static int attempted, install_error = VAU_UNSUPPORTED;

static void publish(uint32_t source, const void *data, size_t length)
{
	if (!atomic_load_explicit(&enabled, memory_order_relaxed) || !length)
		return;

	/* No waiting, allocation, IO, networking or recursive printf in this path. */
	if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire)) {
		atomic_fetch_add_explicit(&dropped, (uint32_t)length, memory_order_relaxed);
		return;
	}

	int32_t pid        = ksceKernelGetProcessId();
	VauTtyRecord *last = ring.latest ? &ring.records[(ring.latest - 1) % VAU_TTY_RECORDS] : NULL;
	uint64_t stamp     = last && ring.sealed != ring.latest && last->source == source &&
                                     last->pid == pid && last->length < VAU_TTY_BYTES
	                             ? last->observed_us
	                             : (uint64_t)ksceKernelGetSystemTimeWide();

	/* A coalesced user line needs one clock read per record, not per character. */
	if (vau_tty_append(&ring, source, pid, data, length, stamp) < 0)
		atomic_fetch_add_explicit(&dropped, (uint32_t)length, memory_order_relaxed);
	atomic_flag_clear_explicit(&busy, memory_order_release);
}

/* The native kernel handler may forward its formatted bytes to putchar.
 * Suppress that echo only on the same thread; simultaneous user output stays. */
static int kernel_echo(void)
{
	if (!atomic_load_explicit(&kernel_calls, memory_order_relaxed))
		return 0;

	uint32_t thread = ksceKernelGetThreadId();

	for (unsigned i = 0; i < 4; i++) {
		if (atomic_load_explicit(&kernel_threads[i], memory_order_relaxed) == thread)
			return 1;
	}
	return 0;
}

static unsigned echo_scope(void)
{
	uint32_t thread = ksceKernelGetThreadId();

	for (unsigned i = 0; i < 4; i++) {
		if (atomic_load_explicit(&kernel_threads[i], memory_order_relaxed) == thread)
			return 0; /* An outer call owns the scope. */
	}
	for (unsigned i = 0; i < 4; i++) {
		uint32_t empty = 0;

		if (atomic_compare_exchange_strong_explicit(&kernel_threads[i], &empty, thread,
		                                            memory_order_relaxed, memory_order_relaxed)) {
			atomic_fetch_add_explicit(&kernel_calls, 1, memory_order_relaxed);
			return i + 1;
		}
	}
	return 0; /* Preserve native output even if every bounded scope is occupied. */
}

static int user_putchar(void *arg, int character)
{
	/* 0x200/0x201 are control markers, not bytes (verified native implementation). */
	if (character != 0x200 && character != 0x201 && !kernel_echo()) {
		unsigned char byte = (unsigned char)character;

		publish(VAU_TTY_USER, &byte, 1);
	}

	return TAI_CONTINUE(int, refs[0], arg, character);
}

static int kernel_printf(void *arg, const char *format, va_list args)
{
	if (atomic_load_explicit(&enabled, memory_order_relaxed)) {
		char text[1024];
		va_list copy;

		va_copy(copy, args);
		int length = vsnprintf(text, sizeof(text), format, copy);

		va_end(copy);
		if (length > 0) {
			size_t kept = (unsigned)length < sizeof(text) ? (unsigned)length : sizeof(text) - 1;

			publish(VAU_TTY_KERNEL, text, kept);
			if ((unsigned)length > kept)
				atomic_fetch_add_explicit(&dropped, (unsigned)length - kept, memory_order_relaxed);
		}
	}

	/* Keep any existing native/debug-plugin handler and its exact return value. */
	unsigned scope = echo_scope();
	int rc         = TAI_CONTINUE(int, refs[1], arg, format, args);

	if (scope) {
		atomic_store_explicit(&kernel_threads[scope - 1], 0, memory_order_relaxed);
		atomic_fetch_sub_explicit(&kernel_calls, 1, memory_order_relaxed);
	}
	return rc;
}

static int allow_kernel_debug(void)
{
	return atomic_load_explicit(&enabled, memory_order_relaxed) ? 1 : TAI_CONTINUE(int, refs[2]);
}

static int allow_system_debug(void)
{
	return atomic_load_explicit(&enabled, memory_order_relaxed) ? 1 : TAI_CONTINUE(int, refs[3]);
}

/* Decode relocated Thumb MOVW/MOVT r3 without unaligned word accesses. */
static int address_half(const unsigned char *text, unsigned opcode, uint32_t *value)
{
	unsigned first  = text[0] | (unsigned)text[1] << 8;
	unsigned second = text[2] | (unsigned)text[3] << 8;

	if ((first & 0xfbf0) != opcode || (second & 0x8f00) != 0x0300)
		return VAU_UNSUPPORTED;

	*value = (first & 15) << 12 | (first & 0x400) << 1 | (second & 0x7000) >> 4 | (second & 255);
	return VAU_OK;
}

static int install(void)
{
	tai_module_info_t module = { .size = sizeof(module) };
	SceKernelModuleInfo info = { .size = sizeof(info) };
	int rc                   = taiGetModuleInfoForKernel(0x10005, "SceSysmem", &module);

	if (rc < 0)
		return rc;
	if (module.module_nid != 0x4DC73B57)
		return VAU_UNSUPPORTED;

	rc = ksceKernelGetModuleInfo(0x10005, module.modid, &info);
	if (rc < 0)
		return rc;
	if (info.segments[0].memsz < 0x19FC0)
		return VAU_UNSUPPORTED;

	const unsigned char *text                   = info.segments[0].vaddr;
	static const unsigned char user_signature[] = { 0xa1, 0xf5, 0x00, 0x73, 0x00, 0xb5, 0x01, 0x2b,
		                                            0x83, 0xb0, 0x04, 0xd9, 0x08, 0x46, 0x01, 0x91,
		                                            0xff, 0xf7, 0xda, 0xff, 0x01, 0x99 };
	static const unsigned char kernel_signature[] = { 0x10, 0xb5 };
	static const unsigned char kernel_tail[]      = { 0x1c, 0x68, 0x14, 0xb1, 0x00, 0x23, 0xa0,
		                                              0x47, 0x10, 0xbd, 0x20, 0x46, 0x10, 0xbd };

	uint32_t low, high;

	/* Verify both relocated address halves against the actual data segment. */
	if (info.segments[1].memsz < 0x5c || address_half(text + 0x19FA8, 0xf240, &low) < 0 ||
	    address_half(text + 0x19FAE, 0xf2c0, &high) < 0 ||
	    (low | high << 16) != (uint32_t)(uintptr_t)info.segments[1].vaddr + 0x58)
		return VAU_UNSUPPORTED;

	/* Verified retail 3.65 dispatchers, including their relocated handler pointer.
	 * Intercept before the callback, preserving native tty/crash-dump storage.
	 * Other firmware must be verified before these offsets are used. */
	if (memcmp(text + 0x19F44, user_signature, sizeof(user_signature)) ||
	    memcmp(text + 0x19FAC, kernel_signature, sizeof(kernel_signature)) ||
	    memcmp(text + 0x19FB2, kernel_tail, sizeof(kernel_tail)))
		return VAU_UNSUPPORTED;

	ids[0] = taiHookFunctionOffsetForKernel(0x10005, &refs[0], module.modid, 0, 0x19F44, 1,
	                                        user_putchar);
	if (ids[0] >= 0)
		ids[1] = taiHookFunctionOffsetForKernel(0x10005, &refs[1], module.modid, 0, 0x19FA8, 1,
		                                        kernel_printf);
	if (ids[1] >= 0)
		ids[2] = taiHookFunctionExportForKernel(0x10005, &refs[2], "SceSysmem", TAI_ANY_LIBRARY,
		                                        0x382C71E8, allow_kernel_debug);
	if (ids[2] >= 0)
		ids[3] = taiHookFunctionExportForKernel(0x10005, &refs[3], "SceSysmem", TAI_ANY_LIBRARY,
		                                        0xCAD47130, allow_system_debug);

	for (unsigned i = 0; i < 4; i++) {
		if (ids[i] < 0) {
			rc = ids[i];
			for (unsigned j = 0; j < 4; j++) {
				if (ids[j] >= 0)
					taiHookReleaseForKernel(ids[j], refs[j]);
				ids[j] = -1;
			}
			return rc;
		}
	}

	atomic_store_explicit(&enabled, 1, memory_order_relaxed);
	return VAU_OK;
}

int vau_tty_kernel(uint32_t operation, uint32_t after, VauTtyPage *out)
{
	if (operation > 1 || !out)
		return VAU_INVALID;
	if (atomic_flag_test_and_set_explicit(&installing, memory_order_acquire))
		return VAU_BUSY;

	/* On authenticated subscription only; never install hooks at kernel boot. */
	if (!operation && !attempted) {
		attempted     = 1;
		install_error = install();
	}

	if (atomic_flag_test_and_set_explicit(&busy, memory_order_acquire)) {
		atomic_flag_clear_explicit(&installing, memory_order_release);
		return VAU_BUSY;
	}

	int rc = vau_tty_read(&ring, operation ? after : ring.latest, out);

	if (rc >= 0) {
		out->kernel_error = out->user_error = install_error;
		out->dropped                        = atomic_load_explicit(&dropped, memory_order_relaxed);
	}
	atomic_flag_clear_explicit(&busy, memory_order_release);
	atomic_flag_clear_explicit(&installing, memory_order_release);
	return rc;
}
