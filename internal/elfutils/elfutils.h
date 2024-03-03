#ifndef ELFUTILS_H
#define ELFUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

size_t
get_elf_bits(const char *path);

size_t
read_elf_bits(FILE *elf);

int
enum_elf_symbols(const char *path, uint64_t base_address, int (*callback)(char *name, uint64_t address, void *arg), void *arg);

#endif
