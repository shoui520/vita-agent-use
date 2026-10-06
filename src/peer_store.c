/*
 * Copyright (C) 2026 shoui520
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "peer_store.h"
#include "sha256.h"
#include "vita_agent.h"
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <stdint.h>
#include <string.h>

#define PEERS          "ur0:data/vita-agent-use/peers"
#define PEER_MAX_BYTES 8192u
#define ABSENT(rc)     ((uint32_t)(rc) == UINT32_C(0x80010002))

static const char *last_stage = "peer store idle";

const char *vau_peer_store_stage(void)
{
	return last_stage;
}

static int peer_path(const unsigned char *certificate, size_t size, char path[128])
{
	if (!certificate || !size || size > PEER_MAX_BYTES)
		return VAU_INVALID;

	struct vau_sha256 hash;
	unsigned char digest[32];
	static const char hex[] = "0123456789abcdef";

	vau_sha256_init(&hash);
	vau_sha256_update(&hash, certificate, size);
	vau_sha256_finish(&hash, digest);
	memcpy(path, PEERS "/", sizeof(PEERS));
	for (unsigned i = 0; i < 32; i++) {
		path[sizeof(PEERS) + i * 2]     = hex[digest[i] >> 4];
		path[sizeof(PEERS) + i * 2 + 1] = hex[digest[i] & 15];
	}

	memcpy(path + sizeof(PEERS) + 64, ".der", 5);
	return VAU_OK;
}

int vau_peer_match(const unsigned char *certificate, size_t size)
{
	char path[128];
	int rc = peer_path(certificate, size, path);

	if (rc < 0)
		return rc;

	last_stage = "peer certificate read";

	int fd = sceIoOpen(path, SCE_O_RDONLY, 0);

	if (fd < 0)
		return ABSENT(fd) ? 0 : fd;

	SceIoStat stat = { 0 };
	unsigned char chunk[256];
	size_t offset = 0;

	rc = sceIoGetstatByFd(fd, &stat);
	if (rc >= 0 && stat.st_size != (SceOff)size)
		rc = VAU_INVALID;

	while (rc >= 0 && offset < size) {
		size_t bytes = size - offset;

		if (bytes > sizeof(chunk))
			bytes = sizeof(chunk);

		int n = sceIoRead(fd, chunk, bytes);

		if (n <= 0 || (size_t)n > bytes) {
			rc = n < 0 ? n : VAU_DEVICE_ERROR;
			break;
		}

		if (memcmp(chunk, certificate + offset, n)) {
			rc = VAU_INVALID;
			break;
		}

		offset += n;
	}

	int closed = sceIoClose(fd);

	return rc < 0 ? rc : closed < 0 ? closed : 1;
}

int vau_peer_save(const unsigned char *certificate, size_t size)
{
	char path[128], temporary[132];
	int rc = peer_path(certificate, size, path);

	if (rc < 0)
		return rc;

	SceIoStat stat = { 0 };

	last_stage = "peer directory stat";
	rc         = sceIoGetstat(PEERS, &stat);
	if (ABSENT(rc)) {
		last_stage = "peer directory create";
		rc         = sceIoMkdir(PEERS, 0777);
	}

	if (rc < 0)
		return rc;

	rc = vau_peer_match(certificate, size);
	if (rc != 0)
		return rc > 0 ? VAU_OK : rc;

	size_t path_size = strlen(path);

	memcpy(temporary, path, path_size);
	memcpy(temporary + path_size, ".tmp", 5);

	last_stage = "peer temporary create";

	int fd = sceIoOpen(temporary, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);

	if (fd < 0)
		return fd;

	size_t offset = 0;

	last_stage = "peer certificate write";
	while (offset < size) {
		int n = sceIoWrite(fd, certificate + offset, size - offset);

		if (n <= 0 || (size_t)n > size - offset) {
			rc = n < 0 ? n : VAU_DEVICE_ERROR;
			break;
		}

		offset += n;
	}

	if (rc >= 0) {
		last_stage = "peer certificate sync";
		rc         = sceIoSyncByFd(fd, 0);
	}

	int closed = sceIoClose(fd);

	if (rc >= 0 && closed < 0)
		rc = closed;

	/* No existing approval is renamed or removed. A partial .tmp is never trusted. */
	if (rc >= 0) {
		last_stage = "peer certificate rename";
		rc         = sceIoRename(temporary, path);
	}

	if (rc < 0)
		return rc;

	rc = vau_peer_match(certificate, size);
	return rc == 1 ? VAU_OK : rc < 0 ? rc : VAU_DEVICE_ERROR;
}
