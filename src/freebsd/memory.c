/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <libmem/libmem.h>
#include <posixutils/posixutils.h>
#include "consts.h"
#include "ptrace/ptrace.h"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

LM_API lm_size_t LM_CALL
LM_ReadMemoryEx(const lm_process_t *process,
		lm_address_t        source,
		lm_byte_t          *dest,
		lm_size_t           size)
{
	int fd;
	lm_char_t mem_path[LM_PATH_MAX] = { 0 };
	ssize_t rdsize;

	snprintf(mem_path, LM_ARRLEN(mem_path), "%s/%d/mem",
	         PROCFS_PATH, process->pid);

	fd = open(mem_path, O_RDONLY);
	if (fd == -1)
		return 0;

	rdsize = pread(fd, dest, size, (off_t)source);
	close(fd);

	if (rdsize == -1)
		return 0;

	return (lm_size_t)rdsize;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_WriteMemoryEx(const lm_process_t *process,
		 lm_address_t        dest,
		 lm_bytearray_t      source,
		 lm_size_t           size)
{
	int fd;
	lm_char_t mem_path[LM_PATH_MAX] = { 0 };
	ssize_t rdsize;

	snprintf(mem_path, LM_ARRLEN(mem_path), "%s/%d/mem",
	         PROCFS_PATH, process->pid);

	fd = open(mem_path, O_WRONLY);
	if (fd == -1)
		return 0;

	rdsize = pwrite(fd, source, size, (off_t)dest);
	close(fd);

	if (rdsize == -1)
		return 0;

	return (lm_size_t)rdsize;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_ProtMemory(lm_address_t address,
	      lm_size_t    size,
	      lm_prot_t    prot,
	      lm_prot_t   *oldprot_out)
{
	int osprot;
	lm_segment_t segment;
	lm_size_t pagesize;
	
	if (address == LM_ADDRESS_BAD || !LM_CHECK_PROT(prot))
		return LM_FALSE;

	pagesize = getpagesize();

	if (size == 0)
		size = pagesize;

	/* Align address to page size */
	address &= (lm_address_t)-pagesize;

	if (oldprot_out) {
		if (LM_FindSegment(address, &segment))
			*oldprot_out = segment.prot;
		else
			*oldprot_out = LM_PROT_NONE;
	}

	osprot = get_os_prot(prot);
	return mprotect((void *)(uintptr_t)address, size, osprot) != -1 ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_ProtMemoryEx(const lm_process_t *process,
		lm_address_t        address,
		lm_size_t           size,
		lm_prot_t           prot,
		lm_prot_t          *oldprot_out)
{
	long syscall_ret;
	int osprot;
	lm_segment_t segment;
	lm_size_t pagesize;
	
	if (!process || address == LM_ADDRESS_BAD || !LM_CHECK_PROT(prot))
		return LM_FALSE;

	pagesize = getpagesize();

	if (size == 0)
		size = pagesize;

	/* Align address to page size */
	address &= (lm_address_t)-pagesize;

	if (oldprot_out) {
		if (LM_FindSegmentEx(process, address, &segment))
			*oldprot_out = segment.prot;
		else
			*oldprot_out = LM_PROT_NONE;
	}

	if (ptrace_attach(process->pid))
		return LM_FALSE;

	osprot = get_os_prot(prot);

	syscall_ret = ptrace_mprotect(process->pid, process->bits, address, size, osprot);

	ptrace_detach(process->pid);

	return syscall_ret == 0 ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_address_t LM_CALL
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot)
{
	int osprot;
	void *alloc;

	if (!LM_CHECK_PROT(prot))
		return LM_ADDRESS_BAD;

	/* NOTE: The function is page aligned, so if size == 0, it will just allocate a full page */
	if (size == 0)
		size = (lm_size_t)getpagesize();

	osprot = get_os_prot(prot);

	alloc = mmap(NULL, size, osprot, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (alloc == MAP_FAILED)
		return LM_ADDRESS_BAD;

	return (lm_address_t)(uintptr_t)alloc;
}

/********************************/

LM_API lm_address_t LM_CALL
LM_AllocMemoryEx(const lm_process_t *process,
		 lm_size_t           size,
		 lm_prot_t           prot)
{
	long alloc;

	if (!process || !LM_CHECK_PROT(prot))
		return LM_ADDRESS_BAD;

	if (size == 0)
		size = (lm_size_t)getpagesize();

	if (ptrace_attach(process->pid))
		return LM_ADDRESS_BAD;

	alloc = ptrace_alloc(process->pid, process->bits, size, get_os_prot(prot));
	ptrace_detach(process->pid);

	if (alloc == -1)
		return LM_ADDRESS_BAD;

	return (lm_address_t)(unsigned long)alloc;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size)
{
	if (alloc == LM_ADDRESS_BAD)
		return LM_FALSE;
	
	if (size == 0)
		size = (lm_size_t)getpagesize();

	return munmap((void *)(uintptr_t)alloc, size) == 0 ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_FreeMemoryEx(const lm_process_t *process,
		lm_address_t        alloc,
		lm_size_t           size)
{
	long syscall_ret;

	if (!process || alloc == LM_ADDRESS_BAD)
		return LM_FALSE;

	if (size == 0)
		size = getpagesize();

	if (ptrace_attach(process->pid))
		return LM_FALSE;

	syscall_ret = ptrace_free(process->pid, process->bits, alloc, size);

	ptrace_detach(process->pid);

	return syscall_ret == 0 ? LM_TRUE : LM_FALSE;
}
