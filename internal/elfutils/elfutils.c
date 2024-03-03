#include "elfutils.h"
#include <string.h>
#include <assert.h>
#include <elf.h>

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

	/* Check if the bits of the ELF header are valid */
	/* WARN: This does not ensure that the file is actually an ELF file! */
	if (elf_magic[4] != 1 && elf_magic[4] != 2)
		return 0;

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

int
enum_elf32_symbols(FILE *elf, int (*callback)(char *name, uint64_t address, void *arg), void *arg)
{
	
}

int
enum_elf64_symbols(FILE *elf, int (*callback)(char *name, uint64_t address, void *arg), void *arg)
{
	int result = -1;
	Elf64_Ehdr ehdr;
	Elf64_Shdr shstrtab_shdr; /* String table section header (contains only section header strings) */
	char *shstrtab;
	char *section_name;
	Elf64_Shdr symtab_shdr; /* Symbol table section header */
	Elf64_Shdr strtab_shdr; /* String table section header */
	Elf64_Half i;
	Elf64_Shdr shdr;
	char *strtab; /* String table */
	Elf64_Sym sym;
	char *symbol_name;
	size_t count;

	assert(elf != NULL && callback != NULL);

	fseek(elf, 0, SEEK_SET);
	if (fread(&ehdr, sizeof(ehdr), 1, elf) == 0)
		return result;

	/* Read shstrtab section header */
	fseek(elf, ehdr.e_shoff + (ehdr.e_shstrndx * ehdr.e_shentsize), SEEK_SET);
	if (fread(&shstrtab_shdr, sizeof(shstrtab_shdr), 1, elf) == 0)
		return result;

	/* Cache section header string table for easier retrieval */
	shstrtab = (char *)malloc(shstrtab_shdr.sh_size);
	if (!shstrtab)
		return result;
	fseek(elf, shstrtab_shdr.sh_offset, SEEK_SET);
	if (fread(shstrtab, shstrtab_shdr.sh_size, 1, elf) == 0)
		goto SHSTRTAB_EXIT;

	/* Read and store necessary section headers from the ELF file */
	strtab_shdr.sh_offset = 0;
	symtab_shdr.sh_offset = 0;
	fseek(elf, ehdr.e_shoff, SEEK_SET);
	for (i = 0; i < ehdr.e_shnum && (strtab_shdr.sh_offset == 0 || symtab_shdr.sh_offset == 0); ++i) {
		if (fread(&shdr, sizeof(shdr), 1, elf) == 0)
			goto SHSTRTAB_EXIT;

		printf("SHDR TYPE: %d\n", shdr.sh_type);
		printf("SHDR OFFSET: %p\n", (void *)shdr.sh_offset);

		switch (shdr.sh_type) {
		case SHT_SYMTAB:
			/* There is only 1 section with 'SHT_SYMTAB' type, so no extra checking needed */
			symtab_shdr = shdr;
			break;
		case SHT_STRTAB:
			section_name = &shstrtab[shdr.sh_name];
			if (!strcmp(section_name, ".strtab"))
				strtab_shdr = shdr;
			break;
		};
	}

	if (symtab_shdr.sh_offset == 0 || strtab_shdr.sh_offset == 0)
		goto SHSTRTAB_EXIT;

	/* Cache string table in memory for easier retrieval */
	strtab = (char *)malloc(strtab_shdr.sh_size);
	if (!strtab)
		goto SHSTRTAB_EXIT;
	fseek(elf, strtab_shdr.sh_offset, SEEK_SET);
	if (fread(strtab, 1, strtab_shdr.sh_size, elf) != strtab_shdr.sh_size)
		goto STRTAB_EXIT;

	/* Loop through symbol table */
	fseek(elf, symtab_shdr.sh_offset, SEEK_SET);
	for (i = 0; i < (symtab_shdr.sh_size / symtab_shdr.sh_entsize); ++i) {
		if (fread(&sym, sizeof(sym), 1, elf) == 0)
			goto STRTAB_EXIT;

		if (sym.st_name == 0)
			continue;

		symbol_name = &strtab[sym.st_name];
		if (!callback(symbol_name, (uint64_t)sym.st_value, arg))
			break;
	}

	result = 0;
STRTAB_EXIT:
	free(strtab);
SHSTRTAB_EXIT:
	free(shstrtab);
	return result;
}

int
enum_elf_symbols(const char *path, int (*callback)(char *name, uint64_t address, void *arg), void *arg)
{
	int result = -1;
	FILE *elf;
	size_t bits;

	assert(path != NULL);

	elf = fopen(path, "r");
	if (!elf)
		return result;

	bits = read_elf_bits(elf);
	if (bits == 0)
		goto CLOSE_EXIT;

	if (bits == 32)
		result = enum_elf32_symbols(elf, callback, arg);
	else if (bits == 64)
		result = enum_elf64_symbols(elf, callback, arg);

CLOSE_EXIT:
	fclose(elf);
	return result;
}
