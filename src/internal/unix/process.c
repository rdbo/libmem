#include "internal.h"

LM_PRIVATE lm_pid_t
_LM_GetProcessId(lm_void_t)
{
	return (lm_pid_t)getpid();
}

/********************************/

LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t)
{
	return (lm_pid_t)getppid();
}

/********************************/

LM_PRIVATE lm_size_t
_LM_GetProcessPath(lm_char_t *pathbuf,
		   lm_size_t  maxlen)
{
	return _LM_GetProcessPathEx(_LM_GetProcessId(), pathbuf, maxlen);
}

/********************************/

LM_PRIVATE lm_void_t
_LM_GetSystemBits(lm_size_t *bits)
{
	struct utsname utsbuf;

	if (uname(&utsbuf))
		return;
		
	if (!LM_STRCMP(utsbuf.machine, LM_STR("x86_64")) ||
	    !LM_STRCMP(utsbuf.machine, LM_STR("amd64")) ||
	    !LM_STRCMP(utsbuf.machine, LM_STR("aarch64")))
		*bits = 64;
}

/********************************/

LM_PRIVATE lm_size_t
_LM_GetElfBits(lm_char_t *path)
{
	lm_size_t bits = 0;
	int fd;
	unsigned char elf_num;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return bits;

	/*
	 * ELF Magic:
	 * 32 bits -> 0x7F, E, L, F, 1
	 * 64 bits -> 0x7F, E, L, F, 2
	 */

	lseek(fd, EI_MAG3 + 1, SEEK_SET);
	if (read(fd, &elf_num, sizeof(elf_num)) > 0 &&
	    (elf_num == 1 || elf_num == 2))
		bits = elf_num * 32;

	close(fd);

	return bits;
}

LM_PRIVATE lm_size_t
_LM_GetProcessBitsEx(lm_char_t *elfpath)
{
	lm_size_t elf_bits;

	elf_bits = _LM_GetElfBits(elfpath);
	if (!elf_bits)
		elf_bits = LM_BITS;

	return elf_bits;
}
