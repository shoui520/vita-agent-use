/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "net_vita.h"
#include "vita_agent.h"
#include <psp2/net/net.h>
#include <psp2/kernel/threadmgr.h>
#include <mbedtls/ssl.h>
#include <limits.h>
#include <string.h>

void vau_net_socket_init(struct vau_net_socket *s)
{
	s->fd    = -1;
	s->error = 0;
}

static int net_error(struct vau_net_socket *s, int rc)
{
	int *value = sceNetErrnoLoc();

	s->error = rc == -1 && value ? *value : rc;
	return s->error == SCE_NET_EAGAIN || s->error == SCE_NET_EINTR ||
	       (unsigned)s->error == SCE_NET_ERROR_EAGAIN || (unsigned)s->error == SCE_NET_ERROR_EINTR;
}

void vau_net_close(struct vau_net_socket *s)
{
	if (!s || s->fd < 0)
		return;

	int fd = s->fd;

	s->fd = -1;

	int rc = sceNetSocketClose(fd);

	if (rc < 0)
		(void)net_error(s, rc);
}

static int nonblocking(struct vau_net_socket *s)
{
	int enabled = 1;
	int rc =
	        sceNetSetsockopt(s->fd, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &enabled, sizeof(enabled));

	if (rc < 0) {
		(void)net_error(s, rc);
		vau_net_close(s);
		return VAU_DEVICE_ERROR;
	}

	return VAU_OK;
}

int vau_net_listen(struct vau_net_socket *s, uint16_t port)
{
	if (!s || s->fd >= 0 || !port)
		return VAU_INVALID;

	s->error = 0;

	int fd = sceNetSocket("vau-command", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);

	if (fd < 0) {
		(void)net_error(s, fd);
		return VAU_DEVICE_ERROR;
	}

	s->fd = fd;
	if (nonblocking(s) < 0)
		return VAU_DEVICE_ERROR;

	SceNetSockaddrIn address;

	memset(&address, 0, sizeof(address));
	address.sin_len         = sizeof(address);
	address.sin_family      = SCE_NET_AF_INET;
	address.sin_port        = sceNetHtons(port);
	address.sin_addr.s_addr = SCE_NET_INADDR_ANY;

	int rc = sceNetBind(fd, (SceNetSockaddr *)&address, sizeof(address));

	if (rc >= 0)
		rc = sceNetListen(fd, 1);
	if (rc < 0) {
		(void)net_error(s, rc);
		vau_net_close(s);
		return VAU_DEVICE_ERROR;
	}

	return VAU_OK;
}

int vau_net_accept(struct vau_net_socket *listener, struct vau_net_socket *client)
{
	if (!listener || !client || listener->fd < 0 || client->fd >= 0)
		return VAU_INVALID;

	int fd = sceNetAccept(listener->fd, NULL, NULL);

	if (fd < 0)
		return net_error(listener, fd) ? 1 : VAU_DEVICE_ERROR;

	client->fd    = fd;
	client->error = 0;
	return nonblocking(client);
}

int vau_net_send(void *context, const unsigned char *data, size_t size)
{
	struct vau_net_socket *s = context;

	if (!s || s->fd < 0 || !data || !size || size > INT_MAX)
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

	int rc = sceNetSend(s->fd, data, (unsigned)size, 0);

	if (rc > 0)
		return rc;
	if (rc < 0 && net_error(s, rc))
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

int vau_net_recv(void *context, unsigned char *data, size_t size)
{
	struct vau_net_socket *s = context;

	if (!s || s->fd < 0 || !data || !size || size > INT_MAX)
		return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;

	int rc = sceNetRecv(s->fd, data, (unsigned)size, 0);

	if (rc >= 0)
		return rc;
	return net_error(s, rc) ? MBEDTLS_ERR_SSL_WANT_READ : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

void vau_net_waiter_init(struct vau_net_waiter *w)
{
	w->id = w->fd = -1;
	w->error      = 0;
	w->events     = 0;
}

int vau_net_waiter_open(struct vau_net_waiter *w)
{
	if (!w || w->id >= 0)
		return VAU_INVALID;

	int rc = sceNetEpollCreate("vau-worker", 0);

	if (rc < 0) {
		w->error = rc;
		return VAU_DEVICE_ERROR;
	}

	w->id = rc;
	return VAU_OK;
}

int vau_net_waiter_detach(struct vau_net_waiter *w)
{
	if (!w)
		return VAU_INVALID;
	if (w->fd < 0)
		return VAU_OK;

	int rc = sceNetEpollControl(w->id, SCE_NET_EPOLL_CTL_DEL, w->fd, NULL);

	if (rc < 0) {
		w->error = rc;
		return VAU_DEVICE_ERROR;
	}

	w->fd     = -1;
	w->events = 0;
	return VAU_OK;
}

int vau_net_waiter_close(struct vau_net_waiter *w)
{
	if (!w)
		return VAU_INVALID;
	if (w->id < 0)
		return VAU_OK;

	int rc = sceNetEpollDestroy(w->id);

	if (rc < 0) {
		w->error = rc;
		return VAU_DEVICE_ERROR;
	}

	w->id = w->fd = -1;
	w->events     = 0;
	return VAU_OK;
}

int vau_net_wait(struct vau_net_waiter *w, struct vau_net_socket *s, unsigned write,
                 unsigned timeout_us)
{
	if (!w || w->id < 0 || !s || s->fd < 0 || write > 1 || timeout_us > 16000)
		return VAU_INVALID;

	unsigned events = write ? SCE_NET_EPOLLOUT : SCE_NET_EPOLLIN;

	if (w->fd != s->fd && vau_net_waiter_detach(w) < 0)
		return VAU_DEVICE_ERROR;
	if (w->fd < 0 || w->events != events) {
		SceNetEpollEvent event = { 0 };

		event.events  = events;
		event.data.fd = s->fd;

		int rc = sceNetEpollControl(
		        w->id, w->fd < 0 ? SCE_NET_EPOLL_CTL_ADD : SCE_NET_EPOLL_CTL_MOD, s->fd, &event);

		if (rc < 0) {
			w->error = rc;

			return VAU_DEVICE_ERROR;
		}

		w->fd     = s->fd;
		w->events = events;
	}

	SceNetEpollEvent event = { 0 };
	int rc                 = sceNetEpollWait(w->id, &event, 1, (int)timeout_us);

	if (rc < 0) {
		if (net_error(s, rc))
			return 0;

		w->error = s->error;
		return VAU_DEVICE_ERROR;
	}

	if (!rc)
		return 0;
	if (rc != 1 || event.data.fd != s->fd)
		return VAU_DEVICE_ERROR;

	/* Let recv/send report EOF/native errors after a HUP/ERR readiness event. */
	return (event.events & (events | SCE_NET_EPOLLHUP | SCE_NET_EPOLLERR)) ? 1 : 0;
}

int vau_net_pause(unsigned timeout_us)
{
	if (!timeout_us || timeout_us > 16000)
		return VAU_INVALID;
	return sceKernelDelayThread(timeout_us);
}
