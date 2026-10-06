/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef VAU_DECRYPT_H_INTERNAL
#define VAU_DECRYPT_H_INTERNAL
#include <stddef.h>
#include <stdint.h>
#include "vau_decrypt.h"

#define VAU_DECRYPT_SEGMENTS 32u
#define VAU_DECRYPT_MAX_ELF  (256u * 1024u * 1024u)

struct vau_elf_header {
	unsigned char ident[16];
	uint16_t type, machine;
	uint32_t version, entry, phoff, shoff, flags;
	uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
};

struct vau_elf_program {
	uint32_t type, offset, vaddr, paddr, filesz, memsz, flags, align;
};

struct vau_self_segment {
	uint64_t offset, length, compression, encryption;
};

struct vau_self_layout {
	struct vau_elf_header elf;
	struct vau_elf_program programs[VAU_DECRYPT_SEGMENTS];
	struct vau_self_segment segments[VAU_DECRYPT_SEGMENTS];
	uint32_t header_bytes, output_bytes, self_type;
};

/* Validate every range before native authentication or output creation. */
int vau_self_parse(const void *, size_t, uint64_t, struct vau_self_layout *);
int vau_vita_decrypt(void *, uint64_t, const char *, const char *, const char *, int, char *,
                     size_t);
int vau_vita_decrypt_busy(void);
void vau_vita_decrypt_poll(void);
#endif
