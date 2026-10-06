/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SELF authentication/PFS flow adapted from TeamFAPS FAGDec (GPL-3.0). */
#include "decrypt.h"
#include "native_ops.h"
#include "content_sdk.h"
#include "content_runtime.h"
#include "package_install.h"
#include "writes_vita.h"
#include "format.h"
#include "json.h"
#include "sha256.h"
#include "write_journal.h"
#include <psp2/appmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/dirent.h>
#include <psp2/io/stat.h>
#include <psp2/npdrm.h>
#include <psp2/kernel/threadmgr.h>
#include <stdatomic.h>
#include <string.h>
#include <zlib.h>

extern void *vauPafMalloc(size_t);
extern void vauPafFree(void *);
#define ROOT "ux0:data/vita-agent-use-decrypt"

static struct {
	struct vau_content_worker worker;
	char id[33], subject[65], path[512], output[128], digest[65];
	unsigned initialized, running, uncertain;
	struct vau_write_journal journal;
	struct vau_write_record record;
	int result;
	uint32_t bytes;
	atomic_uint phase, segment, written;
} job;

enum {
	PHASE_MOUNT,
	PHASE_HEADER,
	PHASE_AUTH,
	PHASE_SEGMENTS,
	PHASE_HASH,
	PHASE_DONE,
	PHASE_SELECT,
	PHASE_READ,
	PHASE_BLOCK,
	PHASE_INFLATE,
	PHASE_WRITE
};

static int read_exact(int fd, void *buffer, unsigned length)
{
	unsigned done = 0;

	while (done < length) {
		int rc = sceIoRead(fd, (char *)buffer + done, length - done);

		if (rc <= 0)
			return rc < 0 ? rc : VAU_DEVICE_ERROR;
		done += rc;
	}
	return 0;
}

static int write_exact(int fd, const void *buffer, unsigned length)
{
	unsigned done = 0;

	while (done < length) {
		int rc = sceIoWrite(fd, (const char *)buffer + done, length - done);

		if (rc <= 0)
			return rc < 0 ? rc : VAU_DEVICE_ERROR;
		done += rc;
	}
	return 0;
}

static void *zallocate(void *unused, unsigned count, unsigned size)
{
	(void)unused;
	if (count && size > SIZE_MAX / count)
		return NULL;
	return vauPafMalloc((size_t)count * size);
}

static void zrelease(void *unused, void *address)
{
	(void)unused;
	vauPafFree(address);
}

static int find_rif(const char *root, const char *title, char out[512])
{
	char directory[512], fixed[48] = { 0 };
	SceIoStat stat;

	vau_snprintf(directory, sizeof(directory), "%slicense/app/%s", root, title);
	int rc = _sceNpDrmGetFixedRifName(fixed, 0);

	if (rc >= 0 && memchr(fixed, 0, sizeof(fixed)) && !strchr(fixed, '/') && fixed[0]) {
		vau_snprintf(out, 512, "%s/%s", directory, fixed);
		if (sceIoGetstat(out, &stat) >= 0 && stat.st_size == 512)
			return 0;
	}

	int fd = sceIoDopen(directory), found = 0;

	if (fd < 0)
		return fd;
	for (unsigned i = 0; i < 256; i++) {
		SceIoDirent entry = { 0 };

		rc = sceIoDread(fd, &entry);
		if (rc <= 0)
			break;
		const char *end = memchr(entry.d_name, 0, sizeof(entry.d_name));
		size_t n        = end ? (size_t)(end - entry.d_name) : sizeof(entry.d_name);

		if (n >= sizeof(entry.d_name)) {
			rc = VAU_INVALID;
			break;
		}
		if (SCE_S_ISREG(entry.d_stat.st_mode) && entry.d_stat.st_size == 512 && n > 4 &&
		    !strcmp(entry.d_name + n - 4, ".rif")) {
			if (found++) {
				rc = VAU_INVALID; /* Ambiguous licenses must not silently select a key. */
				break;
			}
			vau_snprintf(out, 512, "%s/%s", directory, entry.d_name);
		}
		if (i == 255)
			rc = VAU_INVALID;
	}
	sceIoDclose(fd);
	return rc < 0 ? rc : found ? 0 : VAU_INVALID;
}

static int mount_source(char input[512], char mount[16], VauDecryptRequest *request)
{
	strcpy(input, job.path);
	strcpy(request->path, job.path);
	char *colon = strchr(input, ':');

	if (!colon)
		return VAU_INVALID;
	const char *relative = colon + 1;
	int patch            = !strncmp(relative, "patch/", 6);

	if (strncmp(relative, "app/", 4) && !patch)
		return 0;

	const char *title_start = relative + (patch ? 6 : 4);
	char title[10], root[16], app[64], patch_path[64];
	size_t root_bytes = colon + 1 - input;

	if (root_bytes >= sizeof(root) || strlen(title_start) < 11 || title_start[9] != '/')
		return VAU_INVALID;
	memcpy(title, title_start, 9);
	title[9] = 0;
	if (!vau_title_valid(title))
		return VAU_INVALID;
	memcpy(root, input, root_bytes);
	root[root_bytes] = 0;
	vau_snprintf(app, sizeof(app), "%sapp/%s", root, title);
	char pfs[128];
	struct vau_file_info pfs_info;

	vau_snprintf(pfs, sizeof(pfs), "%s/sce_pfs", app);
	int rc = vau_vita_file_stat(NULL, pfs, &pfs_info);

	if ((uint32_t)rc == 0x80010002u)
		return 0; /* Plain homebrew SELF needs no PFS mount or license. */
	if (rc < 0)
		return rc;
	rc = find_rif(root, title, request->rif);

	if (rc < 0)
		return rc;
	vau_snprintf(app, sizeof(app), "%sapp/%s", root, title);
	vau_snprintf(patch_path, sizeof(patch_path), "%spatch/%s", root, title);
	rc = sceAppMgrGameDataMount(app, patch ? patch_path : NULL, request->rif, mount);
	if (rc < 0)
		return rc;
	if (!memchr(mount, 0, 16) || !mount[0])
		return VAU_DEVICE_ERROR;

	vau_snprintf(input, 512, "%s/%s", mount, title_start + 10);
	return 0;
}

static int segment(int source, int target, const struct vau_elf_program *p,
                   const struct vau_self_segment *s, VauDecryptRequest *request,
                   unsigned char *input, unsigned char *output)
{
	if (!p->filesz)
		return 0;
	if (sceIoLseek(source, s->offset, SCE_SEEK_SET) < 0 ||
	    sceIoLseek(target, p->offset, SCE_SEEK_SET) < 0)
		return VAU_DEVICE_ERROR;

	int rc = 0;
	if (s->encryption == 1) {
		atomic_store(&job.phase, PHASE_SELECT);
		request->operation = VAU_DECRYPT_SEGMENT;
		rc                 = vauDecryptSelf(request, NULL);
		if (rc < 0)
			return rc;
		rc = 0;
	}

	uint64_t left    = s->length;
	uint32_t written = 0;
	z_stream stream  = { .zalloc = zallocate, .zfree = zrelease };
	int initialized = 0, ended = 0;

	while (left && !rc) {
		unsigned n = left > VAU_DECRYPT_BLOCK ? VAU_DECRYPT_BLOCK : (unsigned)left;

		atomic_store(&job.phase, PHASE_READ);
		rc = read_exact(source, input, n);
		if (rc < 0)
			break;
		left -= n;
		if (s->encryption == 1) {
			atomic_store(&job.phase, PHASE_BLOCK);
			request->operation = VAU_DECRYPT_BLOCK_OP;
			request->length    = n;
			rc                 = vauDecryptSelf(request, input);
			if (rc < 0)
				break;
			rc = 0;
		}

		if (s->compression == 1) {
			unsigned take = n > p->filesz - written ? p->filesz - written : n;

			rc = write_exact(target, input, take);
			written += take;
		} else if (!ended) {
			if (!initialized) {
				int wrapped = n >= 2 && (input[0] & 15) == 8 &&
				              (((unsigned)input[0] << 8) + input[1]) % 31 == 0;

				atomic_store(&job.phase, PHASE_INFLATE);
				rc = inflateInit2(&stream, wrapped ? 15 : -15);
				if (rc != Z_OK) {
					rc = VAU_DEVICE_ERROR;
					break;
				}
				initialized = 1;
			}
			stream.next_in  = input;
			stream.avail_in = n;
			do {
				stream.next_out  = output;
				stream.avail_out = VAU_DECRYPT_BLOCK;
				atomic_store(&job.phase, PHASE_INFLATE);
				int z         = inflate(&stream, Z_NO_FLUSH);
				unsigned take = VAU_DECRYPT_BLOCK - stream.avail_out;

				if (take > p->filesz - written || (z != Z_OK && z != Z_STREAM_END) ||
				    (!take && stream.avail_in && z != Z_STREAM_END)) {
					rc = VAU_DEVICE_ERROR;
					break;
				}
				rc = write_exact(target, output, take);
				written += take;
				ended = z == Z_STREAM_END;
			} while (!rc && !ended && (!stream.avail_out || stream.avail_in));
		}
		atomic_fetch_add_explicit(&job.written, n, memory_order_relaxed);
		/* Cooperative background worker, not an input/display hook. */
		sceKernelDelayThread(1000);
	}
	if (initialized)
		inflateEnd(&stream);
	if (!rc && (written != p->filesz || (s->compression == 2 && !ended)))
		rc = VAU_DEVICE_ERROR;
	return rc;
}

static int decrypt_worker(void *unused, const char *unused_title)
{
	(void)unused;
	(void)unused_title;
	char input_path[512], mount[16] = { 0 };
	VauDecryptRequest request = { .size = sizeof(request), .operation = VAU_DECRYPT_OPEN };
	struct vau_self_layout layout;
	unsigned char header[VAU_DECRYPT_HEADER];
	int source = -1, target = -1, authenticated = 0, created = 0;
	unsigned char *buffers = NULL;
	int rc                 = mount_source(input_path, mount, &request);

	if (rc < 0)
		goto cleanup;
	atomic_store(&job.phase, PHASE_HEADER);
	source = sceIoOpen(input_path, SCE_O_RDONLY, 0);
	if (source < 0) {
		rc = source;
		goto cleanup;
	}
	SceOff size = sceIoLseek(source, 0, SCE_SEEK_END);

	if (size < 128 || sceIoLseek(source, 0, SCE_SEEK_SET) < 0) {
		rc = VAU_INVALID;
		goto cleanup;
	}
	unsigned header_read = (uint64_t)size < sizeof(header) ? (unsigned)size : sizeof(header);

	rc = read_exact(source, header, header_read);
	if (!rc)
		rc = vau_self_parse(header, header_read, size, &layout);
	if (rc < 0)
		goto cleanup;

	int encrypted = 0;

	for (unsigned i = 0; i < layout.elf.phnum; i++)
		encrypted |= layout.programs[i].filesz && layout.segments[i].encryption == 1;
	if (encrypted) {
		atomic_store(&job.phase, PHASE_AUTH);
		request.length    = layout.header_bytes;
		request.self_type = layout.self_type == 2 || !strncmp(job.path, "os0:", 4) ? 0 : 1;
		rc                = vauDecryptSelf(&request, header);
		if (rc < 0)
			goto cleanup;
		authenticated = 1;
	}

	buffers = vauPafMalloc(2 * VAU_DECRYPT_BLOCK);
	if (!buffers) {
		rc = VAU_DEVICE_ERROR;
		goto cleanup;
	}
	target = sceIoOpen(job.output, SCE_O_RDWR | SCE_O_CREAT | SCE_O_EXCL, 0777);
	if (target < 0) {
		rc = target;
		goto cleanup;
	}
	created = 1;
	atomic_store(&job.phase, PHASE_WRITE);
	rc = write_exact(target, &layout.elf, sizeof(layout.elf));
	if (!rc && sceIoLseek(target, layout.elf.phoff, SCE_SEEK_SET) < 0)
		rc = VAU_DEVICE_ERROR;
	if (!rc)
		rc = write_exact(target, layout.programs, layout.elf.phnum * sizeof(layout.programs[0]));
	if (!rc)
		atomic_store(&job.phase, PHASE_SEGMENTS);
	for (unsigned i = 0; !rc && i < layout.elf.phnum; i++) {
		atomic_store(&job.segment, i);
		request.segment = i;
		rc = segment(source, target, &layout.programs[i], &layout.segments[i], &request, buffers,
		             buffers + VAU_DECRYPT_BLOCK);
	}

	if (!rc) {
		atomic_store(&job.phase, PHASE_HASH);
		SceOff output_size = sceIoLseek(target, 0, SCE_SEEK_END);
		struct vau_sha256 hash;
		unsigned char digest[32];

		if (output_size != layout.output_bytes || sceIoLseek(target, 0, SCE_SEEK_SET) < 0) {
			rc = VAU_DEVICE_ERROR;
			goto cleanup;
		}
		vau_sha256_init(&hash);
		uint32_t left = layout.output_bytes;

		while (left && !rc) {
			unsigned n = left > VAU_DECRYPT_BLOCK ? VAU_DECRYPT_BLOCK : left;

			rc = read_exact(target, buffers, n);
			if (!rc)
				vau_sha256_update(&hash, buffers, n);
			left -= n;
		}
		if (!rc) {
			vau_sha256_finish(&hash, digest);
			for (unsigned i = 0; i < 32; i++)
				vau_snprintf(job.digest + 2 * i, 3, "%02x", digest[i]);
			job.bytes = layout.output_bytes;
		}
		if (!rc)
			rc = sceIoSyncByFd(target, 0);
	}
cleanup:
	if (authenticated) {
		request.operation = VAU_DECRYPT_FINISH;
		int finished      = vauDecryptSelf(&request, NULL);

		if (!rc && finished < 0)
			rc = finished;
	}
	if (source >= 0)
		sceIoClose(source);
	if (target >= 0) {
		int closed = sceIoClose(target);

		if (!rc && closed < 0)
			rc = closed;
	}
	if (mount[0]) {
		int unmounted = sceAppMgrUmount(mount);

		if (!rc && unmounted < 0)
			rc = unmounted;
	}
	if (buffers)
		vauPafFree(buffers);
	if (rc < 0 && created)
		sceIoRemove(job.output);
	return rc;
}

void vau_vita_decrypt_poll(void)
{
	if (!job.running)
		return;
	int rc = vau_content_worker_poll(&job.worker, &job.result);

	if (rc)
		return;
	job.record.phase       = VAU_WRITE_COMPLETE;
	job.record.result      = job.result;
	job.record.observed_us = sceKernelGetSystemTimeWide();
	strcpy(job.record.detail, job.result < 0 ? "self-failed" : "self-complete");
	strcpy(job.record.request.sha256, job.result < 0 ? "" : job.digest);
	struct vau_file_info info;
	int observed = vau_vita_file_stat(NULL, job.output, &info);

	job.record.after =
	        (struct vau_write_observation){ observed == 0                       ? VAU_STATE_FILE
		                                    : (uint32_t)observed == 0x80010002u ? VAU_STATE_MISSING
		                                                                        : VAU_STATE_UNKNOWN,
		                                    observed == 0 ? info.bytes : 0 };
	rc         = vau_journal_append(&job.journal, &job.record);
	int closed = vau_journal_close(&job.journal);

	if (rc < 0 || closed < 0)
		job.result = rc < 0 ? rc : closed;
	job.running = 0;
	if (job.result >= 0)
		atomic_store(&job.phase, PHASE_DONE);
}

int vau_vita_decrypt_busy(void)
{
	return job.running;
}

static int decrypt_status(char *out, size_t capacity)
{
	static const char *const phases[] = { "mounting",   "header",  "authenticating", "segments",
		                                  "hashing",    "done",    "segment_auth",   "read",
		                                  "block_auth", "inflate", "write" };
	char quoted[1027];

	if (vau_json_quote(job.path, quoted, sizeof(quoted)) < 0)
		return VAU_INVALID;
	return vau_snprintf(
	        out, capacity,
	        "{\"operation_id\":\"%s\",\"path\":%s,\"state\":\"%s\",\"running\":%s,"
	        "\"phase\":\"%s\",\"segment\":%u,\"processed_bytes\":\"%u\","
	        "\"native_result\":%d,\"output_path\":\"%s\",\"bytes\":\"%u\",\"sha256\":\"%s\"}",
	        job.id, quoted,
	        job.running      ? "running"
	        : job.uncertain  ? "uncertain"
	        : job.result < 0 ? "failed"
	                         : "complete",
	        job.running ? "true" : "false", phases[atomic_load(&job.phase)],
	        atomic_load(&job.segment), atomic_load(&job.written), job.running ? 0 : job.result,
	        job.output, job.running ? 0 : job.bytes, job.running ? "" : job.digest);
}

int vau_vita_decrypt(void *unused, uint64_t handle, const char *subject, const char *id,
                     const char *path, int start, char *out, size_t capacity)
{
	(void)unused;
	(void)handle;
	if (!subject || strlen(subject) != 64 || !id || strlen(id) != 32)
		return VAU_INVALID;

	vau_vita_decrypt_poll();
	if (!job.initialized || strcmp(job.id, id) || strcmp(job.subject, subject)) {
		if (job.running)
			return VAU_BUSY;
		struct vau_write_journal journal = { 0 };
		struct vau_write_record record;
		int previous = start ? vau_journal_open(&journal, "ur0:data/vita-agent-use/write-audit.db")
		                     : vau_journal_open_readonly(&journal,
		                                                 "ur0:data/vita-agent-use/write-audit.db");

		if (previous < 0)
			return previous;
		previous   = vau_journal_state(&journal, subject, id, &record);
		int closed = vau_journal_close(&journal);

		if (closed < 0)
			return closed;
		if (!previous) {
			char expected[128];

			vau_snprintf(expected, sizeof(expected), ROOT "/%s.elf", id);
			if (record.request.operation != VAU_FS_DECRYPT ||
			    strcmp(record.effect_path, expected) ||
			    (start && strcmp(record.request.path, path)))
				return VAU_STALE;
			memset(&job, 0, sizeof(job));
			job.initialized = 1;
			job.uncertain   = record.phase != VAU_WRITE_COMPLETE;
			job.record      = record;
			job.result      = record.result;
			job.bytes       = (uint32_t)record.after.bytes;
			strcpy(job.id, id);
			strcpy(job.subject, subject);
			strcpy(job.path, record.request.path);
			strcpy(job.output, expected);
			strcpy(job.digest, record.request.sha256);
			atomic_init(&job.phase, PHASE_DONE);
			atomic_init(&job.segment, 0);
			atomic_init(&job.written, 0);
			return decrypt_status(out, capacity);
		}
		if (previous != 1 || !start)
			return previous == 1 ? VAU_STALE : previous;
		if (job.running || vau_vita_content_busy() || vau_vita_install_busy() ||
		    vau_vita_approval_pending(NULL))
			return VAU_BUSY;

		char normalized[512];
		struct vau_file_policy policy;
		struct vau_file_info info;
		int rc = vau_path_normalize(path, normalized, sizeof(normalized));

		if (rc || strcmp(normalized, path))
			return VAU_INVALID;
		rc = vau_vita_acl_load(&policy);
		if (!rc && vau_policy_evaluate(&policy, subject, VAU_FS_READ, path, 0) != VAU_POLICY_ALLOW)
			rc = VAU_DENIED;
		if (!rc)
			rc = vau_vita_file_stat(NULL, path, &info);
		if (!rc && (info.kind != VAU_FILE_REGULAR || info.bytes < 128 || info.bytes > UINT32_MAX))
			rc = VAU_INVALID;
		char output_path[128];

		vau_snprintf(output_path, sizeof(output_path), ROOT "/%s.elf", id);
		if (!rc &&
		    vau_policy_evaluate(&policy, subject, VAU_FS_WRITE, output_path, 0) != VAU_POLICY_ALLOW)
			rc = VAU_DENIED;
		if (!rc) {
			rc = sceIoMkdir(ROOT, 0777);
			if ((uint32_t)rc == 0x80010011u)
				rc = 0;
		}
		if (!rc) {
			rc = vau_vita_file_stat(NULL, ROOT, &info);
			if (!rc && info.kind != VAU_FILE_DIRECTORY)
				rc = VAU_INVALID;
		}
		if (!rc) {
			int exists = vau_vita_file_stat(NULL, output_path, &info);

			if ((uint32_t)exists != 0x80010002u)
				rc = exists < 0 ? exists : VAU_STALE;
		}
		if (rc < 0)
			return rc;

		memset(&job, 0, sizeof(job));
		job.initialized = 1;
		strcpy(job.id, id);
		strcpy(job.subject, subject);
		strcpy(job.path, path);
		strcpy(job.output, output_path);
		atomic_init(&job.phase, PHASE_MOUNT);
		atomic_init(&job.segment, 0);
		atomic_init(&job.written, 0);
		vau_content_worker_init(&job.worker);
		job.record.request.operation = VAU_FS_DECRYPT;
		strcpy(job.record.request.id, id);
		strcpy(job.record.request.subject, subject);
		strcpy(job.record.request.path, path);
		strcpy(job.record.effect_path, job.output);
		strcpy(job.record.detail, "self-decrypt");
		job.record.before.state = VAU_STATE_MISSING;
		job.record.phase        = VAU_WRITE_INTENT;
		job.record.observed_us  = sceKernelGetSystemTimeWide();
		rc = vau_journal_open(&job.journal, "ur0:data/vita-agent-use/write-audit.db");
		if (!rc)
			rc = vau_journal_append(&job.journal, &job.record);
		if (rc < 0) {
			(void)vau_journal_close(&job.journal);
			job.initialized = 0;
			return rc;
		}
		job.record.effect_started = 1;
		rc          = vau_content_worker_start(&job.worker, "DECRYPT01", decrypt_worker, NULL);
		job.running = job.worker.thread >= 0 ||
		              atomic_load_explicit(&job.worker.done, memory_order_acquire);
		if (rc && !job.running) {
			job.result        = rc;
			job.record.phase  = VAU_WRITE_COMPLETE;
			job.record.result = rc;
			strcpy(job.record.detail, "self-failed");
			(void)vau_journal_append(&job.journal, &job.record);
			(void)vau_journal_close(&job.journal);
			atomic_store(&job.phase, PHASE_DONE);
		}
	} else if (start && strcmp(job.path, path)) {
		return VAU_STALE;
	}

	return decrypt_status(out, capacity);
}
