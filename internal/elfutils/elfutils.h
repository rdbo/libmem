#ifndef ELFUTILS_H
#define ELFUTILS_H

#include <stdio.h>
#include <stdlib.h>

size_t
get_elf_bits(const char *path);

size_t
read_elf_bits(FILE *elf);

#endif
