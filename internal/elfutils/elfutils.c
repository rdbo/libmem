#include "elfutils.h"
#include <assert.h>

size_t
read_elf_bits(FILE *elf)
{
	char elf_magic[5];
	size_t elf_magic_len = sizeof(elf_magic) / sizeof(elf_magic[0]);
	
	assert(elf != NULL);

	/*
	 * ELF Magic:
	 * 32 bits -> 0x7F, E, L, F, 1
	 * 64 bits -> 0x7F, E, L, F, 2
	 */

	fseek(elf, 0, SEEK_SET);
	if (fread(elf_magic, sizeof(elf_magic[0]), elf_magic_len, elf) != elf_magic_len) {
		return 0;
	}

	return elf_magic[4] * 32;
}

size_t
get_elf_bits(const char *path)
{
	size_t bits;
	FILE *elf;
	
	bits = sizeof(void *); /* Assume target process bits == size of pointer by default */
	elf = fopen(path, "r");
	if (elf) {
		size_t elf_bits = read_elf_bits(elf);
		if (elf_bits > 0) {
			bits = elf_bits;
		}

		fclose(elf);
	}

	return bits;
}
