/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "decrypt.h"
#include <string.h>

static uint64_t u64(const unsigned char *p)
{
	uint64_t value;

	memcpy(&value, p, sizeof(value));
	return value;
}

static int range(uint64_t offset, uint64_t length, uint64_t size)
{
	return offset <= size && length <= size - offset;
}

int vau_self_parse(const void *data, size_t bytes, uint64_t file_bytes, struct vau_self_layout *out)
{
	const unsigned char *h = data;
	uint32_t magic;

	_Static_assert(sizeof(struct vau_elf_header) == 52, "ELF32 header");
	_Static_assert(sizeof(struct vau_elf_program) == 32, "ELF32 program header");
	if (!h || !out || bytes < 128)
		return VAU_INVALID;

	memcpy(&magic, h, sizeof(magic));
	uint64_t header = u64(h + 16), app = u64(h + 56), elf = u64(h + 64);
	uint64_t ph = u64(h + 72), seg = u64(h + 88);

	if (magic != 0x00454353 || h[10] != 1 || h[11] || header < 128 || header > bytes ||
	    header > VAU_DECRYPT_HEADER || header > file_bytes ||
	    !range(elf, sizeof(out->elf), header) || !range(app, 32, header))
		return VAU_INVALID;

	memset(out, 0, sizeof(*out));
	memcpy(&out->elf, h + elf, sizeof(out->elf));
	memcpy(&out->self_type, h + app + 12, 4);
	struct vau_elf_header *e = &out->elf;

	if (memcmp(e->ident, "\177ELF\1\1\1", 7) || e->machine != 40 || e->version != 1 ||
	    e->ehsize != sizeof(*e) || e->phentsize != sizeof(out->programs[0]) || !e->phnum ||
	    e->phnum > VAU_DECRYPT_SEGMENTS || e->phoff < sizeof(*e) ||
	    !range(e->phoff, (uint64_t)e->phnum * 32, VAU_DECRYPT_MAX_ELF) ||
	    !range(ph, (uint64_t)e->phnum * 32, header) || !range(seg, (uint64_t)e->phnum * 32, header))
		return VAU_INVALID;

	memcpy(out->programs, h + ph, e->phnum * 32);
	memcpy(out->segments, h + seg, e->phnum * 32);
	out->header_bytes = (uint32_t)header;
	out->output_bytes = e->phoff + e->phnum * 32;
	for (unsigned i = 0; i < e->phnum; i++) {
		struct vau_elf_program *p  = &out->programs[i];
		struct vau_self_segment *s = &out->segments[i];

		if (!range(p->offset, p->filesz, VAU_DECRYPT_MAX_ELF) ||
		    !range(s->offset, s->length, file_bytes) ||
		    (s->compression != 1 && s->compression != 2) ||
		    (s->encryption != 1 && s->encryption != 2) ||
		    (p->filesz &&
		     (!s->length || s->offset < header || p->offset < e->phoff + e->phnum * 32)) ||
		    (p->type == 1 && p->filesz > p->memsz) ||
		    (s->compression == 1 && p->filesz > s->length))
			return VAU_INVALID;

		for (unsigned j = 0; j < i && p->filesz; j++) {
			const struct vau_elf_program *q = &out->programs[j];

			if (q->filesz && p->offset < q->offset + q->filesz && q->offset < p->offset + p->filesz)
				return VAU_INVALID;
		}
		if (p->filesz && p->offset + p->filesz > out->output_bytes)
			out->output_bytes = p->offset + p->filesz;
	}

	/* ELF output has no section table; SELF supplies only program segments. */
	e->shoff = e->shnum = e->shentsize = e->shstrndx = 0;
	return 0;
}
