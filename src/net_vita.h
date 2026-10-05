/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef VAU_NET_VITA_H
#define VAU_NET_VITA_H

#include <stddef.h>
#include <stdint.h>

struct vau_net_socket {
	int fd, error;
};

/* User-mode only; SceNet must already be loaded/initialized by the owner.
 * Never initialize or terminate the Shell's shared network stack here.
 * Each socket has one worker owner, and must be initialized before use. */
void vau_net_socket_init(struct vau_net_socket *s);
int vau_net_listen(struct vau_net_socket *s, uint16_t port);

/* Returns 0 on success, 1 for would-block/interruption, negative on failure.
 * Client must be initialized and empty. No crypto is done until accepted. */
int vau_net_accept(struct vau_net_socket *listener, struct vau_net_socket *client);
void vau_net_close(struct vau_net_socket *s);

/* Mbed TLS nonblocking BIO callbacks; errors retained in socket.error. */
int vau_net_send(void *context, const unsigned char *data, size_t size);
int vau_net_recv(void *context, unsigned char *data, size_t size);

/* One socket interest per worker; detach before closing/reusing its descriptor. */
struct vau_net_waiter {
	int id, fd, error;

	unsigned events;
};

void vau_net_waiter_init(struct vau_net_waiter *waiter);
int vau_net_waiter_open(struct vau_net_waiter *waiter);
int vau_net_waiter_detach(struct vau_net_waiter *waiter);
int vau_net_waiter_close(struct vau_net_waiter *waiter);

/* write=0 read, write=1 write. 0 timeout/interruption, 1 ready, negative error.
 * Timeout bounded to 16 ms so the worker can service input expiry and stop. */
int vau_net_pause(unsigned timeout_us);
int vau_net_wait(struct vau_net_waiter *waiter, struct vau_net_socket *socket, unsigned write,
                 unsigned timeout_us);

#endif
