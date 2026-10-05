/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "format.h"
#include "diagnostics_vita.h"
#include "vita_agent.h"
#include <psp2/net/net.h>
#include <psp2/kernel/threadmgr.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static atomic_uint phase;
static atomic_int last_result, log_result;
static atomic_int log_open, log_write, log_close;
static atomic_int notice_result, notice_pending;
static atomic_uint network_stage;
static atomic_int network_result, network_detail, network_close_result, network_close_detail;
static atomic_uint network_close_stage;

void vau_diagnostics_network(unsigned stage, int result, int detail)
{
	if (stage == 5 || stage == 6) {
		atomic_store(&network_close_result, result);
		atomic_store(&network_close_detail, detail);
		atomic_store(&network_close_stage, stage);
	}

	atomic_store_explicit(&network_result, result, memory_order_relaxed);
	atomic_store_explicit(&network_detail, detail, memory_order_relaxed);
	atomic_store_explicit(&network_stage, stage, memory_order_release);
}

static int started;

void vau_diagnostics_notice(int result, int pending)
{
	atomic_store_explicit(&notice_result, result, memory_order_relaxed);
	atomic_store_explicit(&notice_pending, pending, memory_order_release);
}

void vau_diagnostics_io(int opened, int written, int closed)
{
	atomic_store_explicit(&log_open, opened, memory_order_relaxed);
	atomic_store_explicit(&log_write, written, memory_order_relaxed);
	atomic_store_explicit(&log_close, closed, memory_order_relaxed);
}

void vau_diagnostics_update(unsigned value, int result, int logging)
{
	atomic_store_explicit(&last_result, result, memory_order_relaxed);
	atomic_store_explicit(&log_result, logging, memory_order_relaxed);
	atomic_store_explicit(&phase, value, memory_order_release);
}

static int diagnostic_thread(SceSize argc, void *args)
{
	(void)argc;
	(void)args;

	int fd = -1;

	/* Shell's Net initialization may lag this worker. Do not permanently lose
	 * diagnostics after one early failure, and never initialize shared Net. */
	for (unsigned attempt = 0; attempt < 20; attempt++) {
		fd = sceNetSocket("vau-diagnostics", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);
		if (fd >= 0)
			break;
		if (attempt < 19)
			sceKernelDelayThread(500000);
	}

	if (fd < 0)
		return fd;

	SceNetSockaddrIn address = { 0 };

	address.sin_len         = sizeof(address);
	address.sin_family      = SCE_NET_AF_INET;
	address.sin_port        = sceNetHtons(8846);
	address.sin_addr.s_addr = SCE_NET_INADDR_ANY;

	int rc = sceNetBind(fd, (SceNetSockaddr *)&address, sizeof(address));

	if (rc < 0) {
		(void)sceNetSocketClose(fd);
		return rc;
	}

	uint64_t last = 0;
	int replied   = 0;

	for (;;) {
		unsigned char request[64];
		SceNetSockaddrIn peer = { 0 };
		unsigned peer_size    = sizeof(peer);

		rc = sceNetRecvfrom(fd, request, sizeof(request), 0, (SceNetSockaddr *)&peer, &peer_size);
		if (rc < 0)
			break;

		int input           = rc == 6 && !memcmp(request, "input\n", 6);
		int network_request = rc == 8 && !memcmp(request, "network\n", 8);
		int notice_request  = rc == 7 && !memcmp(request, "notice\n", 7);
		int logging_request = rc == 4 && !memcmp(request, "log\n", 4);

		if ((!input && !network_request && !notice_request && !logging_request &&
		     (rc != 7 || memcmp(request, "status\n", 7))) ||
		    peer_size != sizeof(peer) || peer.sin_family != SCE_NET_AF_INET) {
			continue;
		}

		uint64_t now = (uint64_t)sceKernelGetSystemTimeWide();

		if (replied && (now < last || now - last < 1000000))
			continue;

		last    = now;
		replied = 1;
		if (network_request) {
			char response[256];
			int n = vau_snprintf(
			        response, sizeof(response),
			        "{\"v\":1,\"stage\":%u,\"result\":%d,\"detail\":%d,\"close_stage\":%u,\"close_result\":%d,\"close_detail\":%d}",
			        atomic_load_explicit(&network_stage, memory_order_acquire),
			        atomic_load_explicit(&network_result, memory_order_relaxed),
			        atomic_load_explicit(&network_detail, memory_order_relaxed),
			        atomic_load(&network_close_stage), atomic_load(&network_close_result),
			        atomic_load(&network_close_detail));

			if (n > 0 && (size_t)n < sizeof(response)) {
				(void)sceNetSendto(fd, response, (unsigned)n, 0, (SceNetSockaddr *)&peer,
				                   peer_size);
			}
			continue;
		}

		if (notice_request) {
			char response[160];
			int n = vau_snprintf(response, sizeof(response),
			                     "{\"v\":1,\"pending\":%d,\"result\":%d}",
			                     atomic_load_explicit(&notice_pending, memory_order_acquire),
			                     atomic_load_explicit(&notice_result, memory_order_relaxed));

			if (n > 0 && (size_t)n < sizeof(response)) {
				(void)sceNetSendto(fd, response, (unsigned)n, 0, (SceNetSockaddr *)&peer,
				                   peer_size);
			}
			continue;
		}

		if (logging_request) {
			char response[128];
			int n = vau_snprintf(response, sizeof(response),
			                     "{\"v\":1,\"open\":%d,\"write\":%d,\"close\":%d}",
			                     atomic_load_explicit(&log_open, memory_order_relaxed),
			                     atomic_load_explicit(&log_write, memory_order_relaxed),
			                     atomic_load_explicit(&log_close, memory_order_relaxed));

			if (n > 0 && (size_t)n < sizeof(response)) {
				(void)sceNetSendto(fd, response, (unsigned)n, 0, (SceNetSockaddr *)&peer,
				                   peer_size);
			}
			continue;
		}

		if (input) {
			VauInputObservation o = { 0 };
			int query             = vauInputGetObservation(&o);
			char response[512];
			int n = vau_snprintf(
			        response, sizeof(response),
			        "{\"v\":1,\"query\":%d,\"size\":%u,\"abi\":%u,\"stamp\":%llu,\"previous_stamp\":%llu,\"observed_us\":%llu,\"changed_us\":%llu,\"result\":%d,\"error\":%d,\"mask\":%u,\"buttons\":%u,\"reason\":%u,\"sampled\":%u}",
			        query, o.size, o.abi, (unsigned long long)o.stamp,
			        (unsigned long long)o.previous_stamp, (unsigned long long)o.observed_us,
			        (unsigned long long)o.changed_us, o.result, o.error, o.mask, o.buttons,
			        o.reason, o.sampled);

			if (n > 0 && (size_t)n < sizeof(response)) {
				(void)sceNetSendto(fd, response, (unsigned)n, 0, (SceNetSockaddr *)&peer,
				                   peer_size);
			}
			continue;
		}

		VauStopStatus stop = { 0 };
		int query          = vauInputGetStopStatus(&stop);
		unsigned current   = atomic_load_explicit(&phase, memory_order_acquire);
		int result         = atomic_load_explicit(&last_result, memory_order_relaxed);
		int logging        = atomic_load_explicit(&log_result, memory_order_relaxed);
		char response[512];
		int n = vau_snprintf(
		        response, sizeof(response),
		        "{\"v\":1,\"phase\":%u,\"result\":%d,\"log_result\":%d,\"stop_query\":%d,\"stop\":{\"size\":%u,\"abi\":%u,\"ready\":%u,\"held\":%u,\"stopped\":%u,\"error\":%d}}",
		        current, result, logging, query, stop.size, stop.abi, stop.ready, stop.chord_held,
		        stop.stopped, stop.observation_error);

		if (n > 0 && (size_t)n < 256)
			(void)sceNetSendto(fd, response, (unsigned)n, 0, (SceNetSockaddr *)&peer, peer_size);
	}

	(void)sceNetSocketClose(fd);
	return rc;
}

int vau_diagnostics_start(void)
{
	if (started)
		return VAU_BUSY;

	atomic_init(&phase, 0);
	atomic_init(&last_result, 0);
	atomic_init(&log_result, 0);

	int thread = sceKernelCreateThread("VauDiagnostics", diagnostic_thread, 0x10000100, 8192, 0, 0,
	                                   NULL);

	if (thread < 0)
		return thread;

	int rc = sceKernelStartThread(thread, 0, NULL);

	if (rc < 0) {
		(void)sceKernelDeleteThread(thread);
		return rc;
	}

	started = 1;
	return VAU_OK;
}
