/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "performance.h"
#include "format.h"
#include "grant_reply.h"
#include "pairing_flow.h"
#include "command_worker.h"
#include "input_owner.h"
#include "diagnostics_vita.h"
#include "writes_vita.h"
#include "package_install.h"
#include "decrypt.h"
#include "peer_store.h"
#include "acl_vita.h"
#include "content_runtime.h"
#include "native_ops.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/constant_time.h>
#include <stdio.h>
#include <string.h>

#define ROOT         "ur0:data/vita-agent-use/"
#define PAIR_PORT    8847
#define COMMAND_PORT 8848
static struct vau_service service;
static struct vau_tls_server server;

/* Pairing closes before the command worker starts; neither owns live state
 * while the other is running. Reuse their receive storage rather than keeping
 * a second 128 KiB HTTP buffer resident for the lifetime of Shell. */
static union {
	struct vau_pairing_tls pairing;
	struct vau_command_worker commands;
} network;
static struct vau_pairing_worker ui;
static struct vau_pairing_flow flow;
static struct vau_pairing_grant resumed_grant;
static struct vau_notification_worker notifications;
static struct vau_net_socket listener, client;
static struct vau_net_waiter waiter;
static unsigned char certificate[VAU_TLS_CREDENTIAL_BYTES], key[VAU_TLS_CREDENTIAL_BYTES],
        peer[VAU_TLS_CREDENTIAL_BYTES];
static size_t certificate_size, key_size, peer_size;
static uint64_t connection_id;
static int thread = -1;
static void stop_runtime(const char *stage, int result) __attribute__((noreturn));
static void fatal_crypto(int result);

static uint64_t now_us(void)
{
	return sceKernelGetSystemTimeWide();
}

static void prevent_auto_suspend(void)
{
	static uint64_t last_tick;
	uint64_t now = now_us();

	if (!last_tick || now < last_tick || now - last_tick >= UINT64_C(10000000)) {
		(void)sceKernelPowerTick(SCE_KERNEL_POWER_TICK_DISABLE_AUTO_SUSPEND);
		last_tick = now;
	}
}

static int log_event(const char *stage, int result, int detail)
{
	char line[192];
	int n       = vau_snprintf(line, sizeof(line), "[mono_us=%llu] %s: %d detail=%d\n",
	                           (unsigned long long)now_us(), stage, result, detail);
	int fd      = sceIoOpen(ROOT "runtime.log", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
	int logging = fd, written = 0, closed = 0;

	if (fd >= 0) {
		if (n > 0 && (size_t)n < sizeof(line))
			logging = written = sceIoWrite(fd, line, n);
		closed = sceIoClose(fd);
		if (closed < 0)
			logging = closed;
	}

	vau_diagnostics_io(fd, written, closed);
	return logging;
}

static void network_event(unsigned stage, int result, int detail)
{
	vau_diagnostics_network(stage, result, detail);
	if (stage == 5 || stage == 6)
		vau_performance_stop();
	if (stage == 5 || stage == 6 || stage == 7 || stage == 8) {
		log_event(stage == 5   ? "connection closed"
		          : stage == 6 ? "command service closed"
		          : stage == 7 ? "input monitor unavailable"
		                       : "input monitor recovered",
		          result, detail);
	}
}

static void notice_event(int result, int pending)
{
	vau_diagnostics_notice(result, pending);
	if (!pending)
		log_event("notification delivery", result, vau_vita_notification_style_result());
}

static void report(const char *stage, int result)
{
	unsigned phase = 0;

	static const char *const stages[] = {
		"starting",
		"input bridge",
		"identity files",
		"notification worker",
		"pairing listening",
		"pairing start",
		"pairing rejected",
		"native pairing accepted",
		"commands listening",
		"service returning to pairing",
		"crypto worker stopped",
		"network cleanup stopped",
		"trusted session accepted",
		"trusted session rejected",
		"saved peer invalid",
	};
	for (unsigned i = 0; i < sizeof(stages) / sizeof(stages[0]); i++)
		if (!strcmp(stage, stages[i]))
			phase = i;

	int logging = log_event(stage, result, 0);

	vau_diagnostics_update(phase, result, logging);
}

static int read_der(const char *path, unsigned char *out, size_t *size)
{
	*size = 0;

	int fd = sceIoOpen(path, SCE_O_RDONLY, 0);

	if (fd < 0)
		return fd;

	SceIoStat stat = { 0 };
	int rc         = sceIoGetstatByFd(fd, &stat);

	if (rc >= 0 && (stat.st_size <= 0 || stat.st_size > VAU_TLS_CREDENTIAL_BYTES))
		rc = VAU_INVALID;
	while (rc >= 0 && *size < (size_t)stat.st_size) {
		int n = sceIoRead(fd, out + *size, (size_t)stat.st_size - *size);

		if (n <= 0) {
			rc = n < 0 ? n : VAU_DEVICE_ERROR;
			break;
		}

		*size += (size_t)n;
	}

	int closed = sceIoClose(fd);

	if (closed < 0)
		rc = closed;
	if (rc < 0) {
		mbedtls_platform_zeroize(out, VAU_TLS_CREDENTIAL_BYTES);
		*size = 0;
	}

	return rc;
}

/* One atomic file keeps the key and certificate together across power loss. */
static int identity_io(int fd, void *data, size_t size, int writing)
{
	size_t done = 0;

	while (done < size) {
		int n = writing ? sceIoWrite(fd, (unsigned char *)data + done, size - done)
		                : sceIoRead(fd, (unsigned char *)data + done, size - done);

		if (n <= 0)
			return n < 0 ? n : VAU_DEVICE_ERROR;

		done += (size_t)n;
	}

	return 0;
}

/*
 * The device TLS identity, in order of preference:
 *
 *   1. identity.bin: [u32 cert size][u32 key size][cert DER][key DER], with the
 *      file size checked against both lengths before anything is read.
 *   2. Legacy device.der + device-key.der from older builds.
 *   3. A freshly generated identity, written to identity.bin.tmp and renamed
 *      into place so a crash never leaves a half-written identity behind.
 *
 * Generation only happens when nothing exists. A lone device-key.der, or a
 * retained peer.der, means trust state survives without its certificate, and
 * replacing it would silently break pairing, so that is reported instead.
 * 0x80010002 (SCE_ERROR_ERRNO_ENOENT) is the "absent" answer throughout.
 */
static int load_identity(void)
{
	int fd = sceIoOpen(ROOT "identity.bin", SCE_O_RDONLY, 0);

	if (fd >= 0) {
		uint32_t sizes[2] = { 0 };
		SceIoStat stat    = { 0 };
		int rc            = sceIoGetstatByFd(fd, &stat);

		if (rc >= 0)
			rc = identity_io(fd, sizes, sizeof(sizes), 0);
		if (rc >= 0 &&
		    (!sizes[0] || !sizes[1] || sizes[0] > sizeof(certificate) || sizes[1] > sizeof(key) ||
		     stat.st_size != (SceOff)(sizeof(sizes) + sizes[0] + sizes[1]))) {
			rc = VAU_INVALID;
		}

		if (rc >= 0)
			rc = identity_io(fd, certificate, sizes[0], 0);
		if (rc >= 0)
			rc = identity_io(fd, key, sizes[1], 0);

		int closed = sceIoClose(fd);

		if (rc >= 0 && closed < 0)
			rc = closed;
		if (rc >= 0) {
			certificate_size = sizes[0];
			key_size         = sizes[1];
		}

		return rc;
	}

	if ((uint32_t)fd != UINT32_C(0x80010002))
		return fd;

	int rc = read_der(ROOT "device.der", certificate, &certificate_size);

	if (rc >= 0)
		return read_der(ROOT "device-key.der", key, &key_size);
	if ((uint32_t)rc != UINT32_C(0x80010002))
		return rc;

	SceIoStat stat = { 0 };

	/* Never silently replace a partial legacy identity or retained trust. */
	rc = sceIoGetstat(ROOT "device-key.der", &stat);
	if (rc >= 0)
		return VAU_INVALID;
	if ((uint32_t)rc != UINT32_C(0x80010002))
		return rc;

	rc = sceIoGetstat(ROOT "peer.der", &stat);
	if (rc >= 0)
		return VAU_INVALID;
	if ((uint32_t)rc != UINT32_C(0x80010002))
		return rc;

	rc = sceIoGetstat(ROOT "peers", &stat);
	if (rc >= 0)
		return VAU_INVALID;
	if ((uint32_t)rc != UINT32_C(0x80010002))
		return rc;

	rc = vau_tls_generate_identity(&server, certificate, &certificate_size, key, &key_size,
	                               vau_vita_entropy, NULL, fatal_crypto);
	log_event("identity generated", rc, 0);
	if (rc < 0)
		return rc;

	fd = sceIoOpen(ROOT "identity.bin.tmp", SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);
	if (fd < 0) {
		log_event("identity file create", fd, 0);
		return fd;
	}

	uint32_t sizes[2] = { (uint32_t)certificate_size, (uint32_t)key_size };

	rc = identity_io(fd, sizes, sizeof(sizes), 1);
	if (rc >= 0)
		rc = identity_io(fd, certificate, certificate_size, 1);
	if (rc >= 0)
		rc = identity_io(fd, key, key_size, 1);

	int closed = sceIoClose(fd);

	if (rc >= 0 && closed < 0)
		rc = closed;
	if (rc >= 0)
		rc = sceIoRename(ROOT "identity.bin.tmp", ROOT "identity.bin");
	log_event("identity saved", rc, 0);
	return rc;
}

/* Each physical approval adds one certificate without replacing other PCs. */
static int store_peer(void)
{
	int rc = vau_peer_save(network.pairing.certificate, network.pairing.certificate_size);

	if (rc < 0)
		log_event(vau_peer_store_stage(), rc, 0);

	if (rc >= 0) {
		peer_size = network.pairing.certificate_size;
		memcpy(peer, network.pairing.certificate, peer_size);
	}

	return rc;
}

static void close_pair_sockets(void)
{
	/* Retain ownership if native detach/destroy fails; never reuse those fds. */
	if (vau_net_waiter_close(&waiter) < 0)
		stop_runtime("network cleanup stopped", waiter.error ? waiter.error : VAU_DEVICE_ERROR);

	vau_net_close(&client);
	/* Keep admission listening while the command worker owns the TLS arena. */
}

static void stop_runtime(const char *stage, int result)
{
	report(stage, result);
	vau_auth_stop(&service.auth);
	(void)vau_service_poll(&service);

	/* Static module state and any native interests remain owned until reboot.
	 * Do not retry forever, reuse a descriptor or terminate the Shell process. */
	sceKernelExitDeleteThread(result);
	for (;;)
		sceKernelDelayThread(1000000);
}

static void fatal_crypto(int result)
{
	stop_runtime("crypto worker stopped", result);
}

static uint64_t reply_clock(void *context)
{
	(void)context;
	return now_us();
}

static int reply_wait(void *context, int write)
{
	(void)context;
	return vau_net_wait(&waiter, &client, write, 16000);
}

static int token_reply(const struct vau_pairing_grant *grant)
{
	const struct vau_grant_reply_io io = { &server.channel, NULL, reply_clock, reply_wait };

	return vau_grant_reply(&service, grant, COMMAND_PORT, &io);
}

static void unpaired_reply(void)
{
	static const char body[] =
	        "{\"status\":\"error\",\"error\":\"identity_not_paired\","
	        "\"message\":\"Run session pair and approve this identity on the Vita.\"}";
	char reply[384];
	int size = vau_snprintf(reply, sizeof(reply),
	                        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
	                        "Content-Length: %u\r\nConnection: close\r\n\r\n%s",
	                        (unsigned)(sizeof(body) - 1), body);

	if (size <= 0 || (size_t)size >= sizeof(reply))
		return;

	size_t sent      = 0;
	uint64_t started = now_us();

	while (sent < (size_t)size && now_us() - started < UINT64_C(2000000)) {
		int rc = mbedtls_ssl_write(&server.channel, (unsigned char *)reply + sent, size - sent);

		if (rc > 0) {
			sent += rc;
		} else if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (reply_wait(NULL, rc == MBEDTLS_ERR_SSL_WANT_WRITE) < 0)
				break;
		} else {
			break;
		}
	}
}

static int pair_once(void)
{
	/* Admission proves certificate possession but grants no trust. Sessions
	 * require exact saved-certificate equality; pairing requires native OK. */
	int rc = vau_tls_server_init_pairing(
	        &server, (struct vau_tls_der){ certificate, certificate_size },
	        (struct vau_tls_der){ key, key_size }, vau_vita_entropy, NULL, fatal_crypto);

	if (rc < 0)
		return rc;

	vau_net_socket_init(&client);
	vau_net_waiter_init(&waiter);
	rc = vau_net_waiter_open(&waiter);
	if (rc >= 0 && listener.fd < 0) {
		rc = vau_net_listen(&listener, PAIR_PORT);
		if (rc < 0)
			vau_net_close(&listener);
	}

	if (rc < 0)
		goto done;

	/* Start the diagnostic socket only after shared Net accepted our listener.
	 * Starting it at worker entry could precede Shell/companion Net startup. */
	(void)vau_diagnostics_start();
	report("pairing listening", PAIR_PORT);
	for (;;) {
		prevent_auto_suspend();
		(void)vau_service_poll(&service);
		vau_vita_approval_poll(NULL);
		rc = vau_net_wait(&waiter, &listener, 0, 16000);
		if (rc < 0)
			goto done;
		if (!rc)
			continue;

		rc = vau_net_accept(&listener, &client);
		if (rc == 1)
			continue;
		if (rc < 0)
			goto done;
		if (vau_net_waiter_detach(&waiter) < 0) {
			rc = VAU_DEVICE_ERROR;
			goto done;
		}

		if (connection_id == UINT64_MAX) {
			rc = VAU_DENIED;
			goto done;
		}

		rc = vau_tls_server_reset(&server);
		if (rc < 0)
			goto done;

		mbedtls_ssl_set_bio(&server.channel, &client, vau_net_send, vau_net_recv, NULL);
		++connection_id;
		rc = vau_pairing_tls_init(&network.pairing, &server, &service, connection_id, now_us());
		if (rc >= 0)
			vau_http_init_admission(&network.pairing.http);
		if (rc < 0) {
			report("pairing start", rc);
			goto attempt_failed;
		}

		while (!network.pairing.request_ready && network.pairing.work != VAU_TLS_CLOSED) {
			if (network.pairing.work == VAU_TLS_WAIT_READ ||
			    network.pairing.work == VAU_TLS_WAIT_WRITE) {
				int ready = vau_net_wait(&waiter, &client,
				                         network.pairing.work == VAU_TLS_WAIT_WRITE, 16000);

				if (ready < 0) {
					vau_pairing_tls_close(&network.pairing, ready);
					break;
				}
			}

			(void)vau_pairing_tls_request_step(&network.pairing, &service, now_us());
		}

		rc = network.pairing.work == VAU_TLS_CLOSED ? network.pairing.error : VAU_OK;
		if (rc < 0) {
			report("pairing request rejected", rc);
			goto attempt_failed;
		}

		int trusted = vau_peer_match(network.pairing.certificate, network.pairing.certificate_size);

		if (trusted < 0) {
			rc = trusted;
			report("saved peer invalid", rc);
			goto attempt_failed;
		}

		if (network.pairing.http.pairing_only == 2 || trusted) {
			/* Repeated pairing of an approved identity is a silent reconnect. */
			rc = trusted ? VAU_OK : VAU_DENIED;
			if (!trusted)
				unpaired_reply();
			if (trusted) {
				peer_size = network.pairing.certificate_size;
				memcpy(peer, network.pairing.certificate, peer_size);
			}

			if (rc >= 0)
				memcpy(server.peer_fingerprint, network.pairing.binding.certificate_sha256, 32);
			if (rc >= 0) {
				rc = vau_vita_session_activate(
				        &service, &network.pairing.binding, server.peer_fingerprint,
				        notifications.started ? &notifications : NULL, network.pairing.request.name,
				        network.pairing.request.name_length, now_us(), &resumed_grant);
			}

			if (rc >= 0)
				rc = token_reply(&resumed_grant);
			mbedtls_platform_zeroize(&resumed_grant, sizeof(resumed_grant));
			if (rc >= 0) {
				report("trusted session accepted", 0);
				goto done;
			}

			(void)vau_vita_file_list_reset();
			(void)vau_content_legacy_reset();
			while (vau_vita_approval_pending(NULL) || vau_vita_content_inflight()) {
				vau_vita_approval_cancel(NULL);
				vau_vita_approval_poll(NULL);
				sceKernelDelayThread(16000);
			}

			if (!service.auth.stopped)
				vau_auth_stop(&service.auth);
			(void)vau_service_poll(&service);
			report("trusted session rejected", rc);
			vau_pairing_tls_close(&network.pairing, rc);
			goto attempt_failed;
		}

		rc = vau_vita_wake(NULL);
		if (rc >= 0)
			rc = vau_pairing_flow_init(&flow, &network.pairing, &ui);
		if (rc < 0)
			goto attempt_failed;

		do {
			if (network.pairing.work == VAU_TLS_WAIT_READ ||
			    network.pairing.work == VAU_TLS_WAIT_WRITE) {
				int ready = vau_net_wait(&waiter, &client,
				                         network.pairing.work == VAU_TLS_WAIT_WRITE, 16000);

				if (ready < 0)
					vau_pairing_flow_cancel(&flow, ready);
			} else if (network.pairing.work == VAU_TLS_CLOSED) {
				sceKernelDelayThread(16000);
			}

			rc = vau_pairing_flow_step(&flow, now_us());
		} while (rc == VAU_BUSY);
		if (rc == VAU_OK) {
			rc = store_peer();
			if (rc >= 0)
				rc = token_reply(&ui.grant);
			if (rc >= 0) {
				report("native pairing accepted", 0);
				goto done;
			}

			vau_pairing_flow_cancel(&flow, rc);
		}

		report("pairing rejected", rc);
		if (ui.state == VAU_PAIR_WORK_DONE)
			(void)vau_pairing_worker_reset(&ui);
		vau_pairing_tls_close(&network.pairing, rc);
attempt_failed:
		if (vau_net_waiter_detach(&waiter) < 0) {
			rc = VAU_DEVICE_ERROR;
			goto done;
		}

		vau_net_close(&client);

		/* Admission backoff uses short sleeps so stop cleanup remains polled. */
		for (unsigned i = 0; i < 63; i++) {
			(void)vau_service_poll(&service);
			sceKernelDelayThread(16000);
		}
	}
done:
	close_pair_sockets();
	vau_pairing_tls_close(&network.pairing, rc);
	vau_tls_server_free(&server);
	if (ui.state == VAU_PAIR_WORK_DONE)
		(void)vau_pairing_worker_reset(&ui);
	return rc;
}

static int runtime_thread(SceSize args, void *argp)
{
	(void)args;
	(void)argp;
	vau_net_socket_init(&listener);
	(void)vau_diagnostics_start();

	SceIoStat directory_stat = { 0 };
	int directory            = sceIoGetstat("ur0:data", &directory_stat);

	if ((uint32_t)directory == UINT32_C(0x80010002))
		directory = sceIoMkdir("ur0:data", 0777);
	if (directory < 0) {
		report("identity files", directory);
		return 0;
	}

	directory = sceIoGetstat("ur0:data/vita-agent-use", &directory_stat);
	if ((uint32_t)directory == UINT32_C(0x80010002))
		directory = sceIoMkdir("ur0:data/vita-agent-use", 0777);
	if (directory < 0) {
		report("identity files", directory);
		return 0;
	}

	report("starting", 0);
	vau_service_init(&service, &vau_vita_stop_bridge);
	service.stop_notice = vau_ui_agent_stopped;
	vau_vita_writes_init(&service);
	vau_vita_acl_init(&service);
	vau_vita_content_init(&service);
	vau_vita_install_init(&service);

	int rc = vau_service_attach_input(&service, &vau_vita_input_bridge);

	if (rc < 0) {
		report("input bridge", rc);
		return 0;
	}

	rc = load_identity();
	if (rc < 0) {
		report("identity files", rc);
		return 0;
	}

	/* Only peer.previous.der left means store_peer() was interrupted between renames. */
	rc = read_der(ROOT "peer.der", peer, &peer_size);
	if ((uint32_t)rc == UINT32_C(0x80010002)) {
		int previous = read_der(ROOT "peer.previous.der", peer, &peer_size);

		if (previous >= 0)
			rc = sceIoRename(ROOT "peer.previous.der", ROOT "peer.der");
		else if ((uint32_t)previous != UINT32_C(0x80010002))
			rc = previous;
	}

	/* Corrupt trust is a recovery error. New peer approval is explicit and
	 * never silently discards unreadable saved trust. */
	if (rc < 0 && (uint32_t)rc != UINT32_C(0x80010002)) {
		report("saved peer invalid", rc);
		return 0;
	}

	/* Migrate the currently trusted legacy identity once; retain the old file. */
	if (peer_size) {
		rc = vau_peer_save(peer, peer_size);
		if (rc < 0) {
			log_event(vau_peer_store_stage(), rc, 0);
			report("saved peer invalid", rc);
			return 0;
		}
	}

	{
		char result[3500];
		int events = vau_vita_native_api.events
		                     ? vau_vita_native_api.events(NULL, 0, 0, result, sizeof(result))
		                     : VAU_UNSUPPORTED;

		report("default coredump event listener", events < 0 ? events : 0);
	}

	rc = vau_notification_worker_init(&notifications, &service);
	report("notification worker", rc);
	if (rc >= 0) {
		notifications.observer   = notice_event;
		service.activity_context = &notifications;
		service.activity         = vau_notification_worker_activity;
	}

	vau_pairing_worker_init(&ui, &service, &vau_vita_native_api, rc >= 0 ? &notifications : NULL);
	for (;;) {
		rc = pair_once();
		if (rc >= 0) {
			rc = vau_tls_server_init(&server, (struct vau_tls_der){ certificate, certificate_size },
			                         (struct vau_tls_der){ key, key_size },
			                         (struct vau_tls_der){ peer, peer_size }, vau_vita_entropy,
			                         NULL, fatal_crypto);
		}

		if (rc >= 0) {
			rc = vau_command_worker_init(&network.commands, &service, &vau_vita_native_api, &server,
			                             COMMAND_PORT);
			if (rc < 0 && network.commands.initialized) {
				int closed = vau_command_worker_close(&network.commands, rc);

				if (closed < 0) {
					stop_runtime("network cleanup stopped", network.commands.waiter.error
					                                                ? network.commands.waiter.error
					                                                : closed);
				}
			}
		}

		if (rc >= 0) {
			if (notifications.started)
				(void)vau_command_worker_attach_notifications(&network.commands, &notifications);
			network.commands.trace = network_event;
			report("commands listening", COMMAND_PORT);
			vau_net_waiter_init(&waiter);
			rc = vau_net_waiter_open(&waiter);
			if (rc < 0)
				stop_runtime("network cleanup stopped", rc);

			while (network.commands.running) {
				/* A new pairing/session connection waits in the listener backlog
				 * until the current command connection and native work release it.
				 * This reuses the existing TLS arena and preserves live operations. */
				if (!network.commands.connected && !vau_vita_install_busy() &&
				    !vau_vita_decrypt_busy() && !vau_vita_content_inflight()) {
					int waiting = vau_net_wait(&waiter, &listener, 0, 0);

					if (waiting < 0)
						stop_runtime("network cleanup stopped", waiting);
					if (waiting > 0)
						break;
				}

				prevent_auto_suspend();
				(void)vau_command_worker_step(&network.commands);
			}

			if (vau_net_waiter_close(&waiter) < 0)
				stop_runtime("network cleanup stopped", waiter.error);

			rc = network.commands.error;

			int closed = vau_command_worker_close(&network.commands, network.commands.error);

			if (closed < 0) {
				stop_runtime("network cleanup stopped", network.commands.waiter.error
				                                                ? network.commands.waiter.error
				                                                : closed);
			}
		}

		(void)vau_vita_file_list_reset();
		(void)vau_content_legacy_reset();
		while (vau_vita_approval_pending(NULL) || vau_vita_content_inflight()) {
			vau_vita_approval_cancel(NULL);
			vau_vita_approval_poll(NULL);
			sceKernelDelayThread(16000);
		}

		if (!service.auth.stopped)
			vau_auth_stop(&service.auth);
		(void)vau_service_poll(&service);
		vau_tls_server_free(&server);
		report("service returning to pairing", rc);
		for (unsigned i = 0; i < 63; i++) {
			(void)vau_service_poll(&service);
			sceKernelDelayThread(16000);
		}
	}

	return 0;
}

int _start(SceSize argc, const void *args) __attribute__((weak, alias("module_start")));

int module_start(SceSize argc, const void *args)
{
	(void)argc;
	(void)args;
	thread = sceKernelCreateThread("VauService", runtime_thread, 0x10000100, 96 * 1024, 0, 0, NULL);
	if (thread < 0)
		return SCE_KERNEL_START_FAILED;
	if (sceKernelStartThread(thread, 0, NULL) < 0) {
		sceKernelDeleteThread(thread);
		thread = -1;
		return SCE_KERNEL_START_FAILED;
	}

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	(void)argc;
	(void)args;
	return SCE_KERNEL_STOP_CANCEL;
}
