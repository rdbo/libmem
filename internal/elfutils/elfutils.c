#include "elfutils.h"
#include <string.h>
#include <assert.h>
#include <elf.h>

#define ELFW_ST_TYPE(elf) (elf.st_info & 0xf)

#define ENUM_ELFW_SYMBOLS(elf_type) \
int \
enum_elf##elf_type##_symbols(FILE *elf, uint64_t base_address, int (*callback)(char *name, uint64_t address, void *arg), void *arg) \
{ \
	int result = -1; \
	Elf##elf_type##_Ehdr ehdr; \
	Elf##elf_type##_Shdr shstrtab_shdr /* String table section header (contains only section header strings) */; \
	char *shstrtab; \
	char *section_name; \
	Elf##elf_type##_Shdr symtab_shdr; /* Symbol table section header */ \
	Elf##elf_type##_Shdr strtab_shdr; /* String table section header */ \
	Elf##elf_type##_Shdr dynsym_shdr; /* Dynamic symbol table section header */ \
	Elf##elf_type##_Shdr dynstr_shdr; /* Dynamic string table section header */ \
	Elf##elf_type##_Half i; \
	Elf##elf_type##_Shdr shdr; \
	char *strtab; /* String table */ \
	char *dynstr; /* Dynamic string table */\
	Elf##elf_type##_Sym sym; \
	char *symbol_name; \
\
	assert(elf != NULL && callback != NULL); \
\
	fseek(elf, 0, SEEK_SET); \
	if (fread(&ehdr, sizeof(ehdr), 1, elf) == 0) \
		return result; \
\
	/* NOTE: Files with 'ET_EXEC' as the ELF header type have absolute addresses on symbols */ \
	/* TODO: Double check that this is always the case */ \
	if (ehdr.e_type == ET_EXEC) \
		base_address = 0; \
\
	/* Read shstrtab section header */ \
	fseek(elf, ehdr.e_shoff + (ehdr.e_shstrndx * ehdr.e_shentsize), SEEK_SET); \
	if (fread(&shstrtab_shdr, sizeof(shstrtab_shdr), 1, elf) == 0) \
		return result; \
\
	/* Cache section header string table for easier retrieval */ \
	shstrtab = (char *)malloc(shstrtab_shdr.sh_size); \
	if (!shstrtab) \
		return result; \
	fseek(elf, shstrtab_shdr.sh_offset, SEEK_SET); \
	if (fread(shstrtab, shstrtab_shdr.sh_size, 1, elf) == 0) \
		goto SHSTRTAB_EXIT; \
\
	/* Read and store necessary section headers from the ELF file */ \
	strtab_shdr.sh_offset = 0; \
	symtab_shdr.sh_offset = 0; \
	fseek(elf, ehdr.e_shoff, SEEK_SET); \
	for (i = 0; i < ehdr.e_shnum && (strtab_shdr.sh_offset == 0 || symtab_shdr.sh_offset == 0); ++i) { \
		if (fread(&shdr, sizeof(shdr), 1, elf) == 0) \
			goto SHSTRTAB_EXIT; \
\
		switch (shdr.sh_type) { \
		case SHT_SYMTAB: \
			/* There is only 1 section with 'SHT_SYMTAB' type, so no extra checking needed */ \
			symtab_shdr = shdr; \
			break; \
		case SHT_DYNSYM: \
			/* There is only 1 section with 'SHT_DYNSYM' type, so no extra checking needed */ \
			dynsym_shdr = shdr; \
			break; \
		case SHT_STRTAB: \
			section_name = &shstrtab[shdr.sh_name]; \
			if (!strcmp(section_name, ".strtab")) \
				strtab_shdr = shdr; \
			else if (!strcmp(section_name, ".dynstr")) \
				dynstr_shdr = shdr; \
			break; \
		}; \
	} \
\
	if (symtab_shdr.sh_offset != 0 && strtab_shdr.sh_offset != 0) { \
		size_t symcount; \
		/* Cache string table in memory for easier retrieval */ \
		strtab = (char *)malloc(strtab_shdr.sh_size); \
		if (!strtab) \
			goto SHSTRTAB_EXIT; \
		fseek(elf, strtab_shdr.sh_offset, SEEK_SET); \
		if (fread(strtab, 1, strtab_shdr.sh_size, elf) != strtab_shdr.sh_size) \
			goto STRTAB_EXIT; \
\
		/* Loop through symbol table */ \
		fseek(elf, symtab_shdr.sh_offset, SEEK_SET); \
		symcount = symtab_shdr.sh_size / symtab_shdr.sh_entsize; \
		for (i = 0; i < symcount; ++i) { \
			if (fread(&sym, sizeof(sym), 1, elf) == 0) \
				goto STRTAB_EXIT; \
\
			if (sym.st_name == 0 || ELFW_ST_TYPE(sym) == STT_FILE) \
				continue; \
\
			symbol_name = &strtab[sym.st_name]; \
			if (!callback(symbol_name, base_address + (uint64_t)sym.st_value, arg)) \
				break; \
		} \
\
STRTAB_EXIT: /* TODO: Don't return '0' (success) if the fread call fails */ \
		free(strtab); \
\
		if (i < symcount) \
			goto EXIT; \
	} \
\
	if (dynsym_shdr.sh_offset != 0 && dynstr_shdr.sh_offset != 0) { \
		size_t symcount; \
		/* Cache string table in memory for easier retrieval */ \
		dynstr = (char *)malloc(dynstr_shdr.sh_size); \
		if (!dynstr) \
			goto SHSTRTAB_EXIT; \
		fseek(elf, dynstr_shdr.sh_offset, SEEK_SET); \
		if (fread(dynstr, 1, dynstr_shdr.sh_size, elf) != dynstr_shdr.sh_size) \
			goto SHSTRTAB_EXIT; \
\
		/* Loop through symbol table */ \
		fseek(elf, dynsym_shdr.sh_offset, SEEK_SET); \
		symcount = dynsym_shdr.sh_size / dynsym_shdr.sh_entsize; \
		for (i = 0; i < symcount; ++i) { \
			if (fread(&sym, sizeof(sym), 1, elf) == 0) \
				goto DYNSTR_EXIT; \
\
			if (sym.st_name == 0 || ELFW_ST_TYPE(sym) == STT_FILE) \
				continue; \
\
			symbol_name = &dynstr[sym.st_name]; \
			if (!callback(symbol_name, base_address + (uint64_t)sym.st_value, arg)) \
				break; \
		} \
\
DYNSTR_EXIT: /* TODO: Don't return '0' (success) if the fread call fails */ \
		free(dynstr); \
	} \
EXIT: \
	result = 0; \
SHSTRTAB_EXIT: \
	free(shstrtab); \
	return result; \
}

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
	
	bits = sizeof(void *) * 8; /* Assume target process bits == size of pointer by default */
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

/* Generate ELF symbol enumeration functions */
ENUM_ELFW_SYMBOLS(32)
ENUM_ELFW_SYMBOLS(64)

int
enum_elf_symbols(const char *path, uint64_t base_address, int (*callback)(char *name, uint64_t address, void *arg), void *arg)
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
		result = enum_elf32_symbols(elf, base_address, callback, arg);
	else if (bits == 64)
		result = enum_elf64_symbols(elf, base_address, callback, arg);

CLOSE_EXIT:
	fclose(elf);
	return result;
}
