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

#include "../ptrace.h"
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <memory.h>

long
ptrace_get_syscall_ret(pid_t pid)
{
	long ret;
	struct reg regs;

	errno = 0;

	ret = ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0);
	if (ret != -1) {
		ret = regs.r_eax;
	}

	return ret;
}

size_t
ptrace_setup_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys, void **orig_regs, void **orig_code)
{
	static const char shellcode32[] = { 0xcd, 0x80 };
	struct reg regs;
	char *shellcode;
	size_t shellcode_size = 0;

	assert((bits == 64 || bits == 32) && ptsys != NULL && orig_regs != NULL && *orig_regs == NULL && orig_code != NULL && *orig_code == NULL);

	if (ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) == -1)
		return 0;

	*orig_regs = malloc(sizeof(regs));
	if (*orig_regs == NULL)
		return 0;

	*(struct reg *)(*orig_regs) = regs;

	/* Setup registers */
	regs.r_eax = ptsys->syscall_num;
	regs.r_ebx = ptsys->args[0];
	regs.r_ecx = ptsys->args[1];
	regs.r_edx = ptsys->args[2];
	regs.r_esi = ptsys->args[3];
	regs.r_edi = ptsys->args[4];
	regs.r_ebp = ptsys->args[5];
	shellcode = (char *)shellcode32;
	shellcode_size = sizeof(shellcode32);

	/* Setup stack */
	regs.r_esp -= sizeof(ptsys->stack);
	regs.r_esp &= -16UL;
	if (ptrace_write(pid, regs.r_esp, ptsys->stack, sizeof(ptsys->stack)) != sizeof(ptsys->stack))
		goto FREE_REGS_EXIT;

	/* Backup original code to restore later */
	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		goto FREE_REGS_EXIT;

	if (ptrace_read(pid, regs.r_eip, *orig_code, shellcode_size) != shellcode_size)
		goto FREE_EXIT;

	if (ptrace(PT_SETREGS, pid, (caddr_t)&regs, 0) == -1)
		goto FREE_EXIT;

	if (ptrace_write(pid, (long)regs.r_eip, shellcode, shellcode_size) == 0)
		goto CLEAN_EXIT;

	goto EXIT;
CLEAN_EXIT:
	ptrace(PT_SETREGS, pid, (caddr_t)*orig_regs, 0);
FREE_EXIT:
	free(*orig_code);
FREE_REGS_EXIT:
	free(*orig_regs);
	shellcode_size = 0;
EXIT:
	return shellcode_size;
}

void
ptrace_restore_syscall(pid_t pid, void *orig_regs, void *orig_code, size_t shellcode_size)
{
	struct reg *pregs = (struct reg *)orig_regs;

	assert(orig_regs != NULL && orig_code != NULL && shellcode_size > 0);

	ptrace(PT_SETREGS, pid, (caddr_t)pregs, 0);
	ptrace_write(pid, pregs->r_eip, orig_code, shellcode_size);

	free(orig_regs);
	free(orig_code);
}

long
ptrace_alloc(pid_t pid, size_t bits, size_t size, int prot)
{
	long alloc;
	ptrace_syscall_t ptsys;
	
	ptsys.syscall_num = SYS_mmap;

	/* Setup mmap arguments */
	ptsys.args[0] = 0;                      /* `void *addr` */
	ptsys.args[1] = size;                   /* `size_t length` */
	ptsys.args[2] = prot;                   /* `int prot` */
	ptsys.args[3] = MAP_PRIVATE | MAP_ANON; /* `int flags` */
	ptsys.args[4] = -1;                     /* `int fd` */
	ptsys.args[5] = 0;                      /* `off_t offset` */

	/* Setup FreeBSD syscall convention */

	/*
	 * NOTE: There is a pad in the FreeBSD x86 system call:
	 * struct mmap_args {
	 * 	void *addr;
	 * 	size_t len;
	 * 	int prot;
	 * 	int flags;
	 * 	int fd;
	 * 	long pad;
	 * 	off_t pos;
	 * };
	 */
	*(uint32_t *)&ptsys.stack[0] = ptsys.syscall_num;
	*(uint32_t *)&ptsys.stack[4] = 0;                       /* void *addr */
	*(uint32_t *)&ptsys.stack[8] = size;                    /* size_t len */
	*(uint32_t *)&ptsys.stack[12] = prot;                   /* int prot */
	*(uint32_t *)&ptsys.stack[16] = MAP_PRIVATE | MAP_ANON; /* int flags */
	*(uint32_t *)&ptsys.stack[20] = -1;                     /* int fd */
	*(uint32_t *)&ptsys.stack[24] = 0;                      /* long pad */
	*(uint32_t *)&ptsys.stack[28] = 0;                      /* off_t pos */

	alloc = ptrace_syscall(pid, bits, &ptsys);
	if ((alloc == -1 && errno) || (void *)alloc == MAP_FAILED)
		alloc = -1;

	return alloc;
}

long
ptrace_free(pid_t pid, size_t bits, long alloc, size_t size)
{
	ptrace_syscall_t ptsys;

	ptsys.syscall_num = SYS_munmap;

	ptsys.args[0] = alloc; /* `void *addr` */
	ptsys.args[1] = size;  /* `size_t length` */

	/* Setup FreeBSD syscall convention */
	*(uint32_t *)&ptsys.stack[0] = ptsys.syscall_num;
	*(uint32_t *)&ptsys.stack[4] = alloc;
	*(uint32_t *)&ptsys.stack[8] = size;

	return ptrace_syscall(pid, bits, &ptsys);
}

long
ptrace_mprotect(pid_t pid, size_t bits, long addr, size_t size, int prot)
{
	ptrace_syscall_t ptsys;

	ptsys.syscall_num = SYS_mprotect;

	ptsys.args[0] = addr;
	ptsys.args[1] = size;
	ptsys.args[2] = prot;

	/* Setup FreeBSD syscall convention */
	*(uint32_t *)&ptsys.stack[0] = ptsys.syscall_num;
	*(uint32_t *)&ptsys.stack[4] = addr;
	*(uint32_t *)&ptsys.stack[8] = size;
	*(uint32_t *)&ptsys.stack[12] = prot;

	return ptrace_syscall(pid, bits, &ptsys);
}

size_t
ptrace_setup_libcall(pid_t pid, size_t bits, ptrace_libcall_t *ptlib, void **orig_regs, void **orig_code)
{
	const uint8_t shellcode[] = {
		/* call rax */
		0xFF, 0xD0,
		/* int3 */
		0xCC
	};
	size_t shellcode_size = sizeof(shellcode);
	struct reg regs;

	assert((bits == 32 || bits == 64) && ptlib && orig_regs && orig_code);

	if (ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) == -1)
		return 0;

	*orig_regs = malloc(sizeof(regs));
	if (*orig_regs == NULL)
		return 0;
	**(struct reg **)orig_regs = regs;

	/* Setup stack */
	regs.r_eax = ptlib->address;
	regs.r_esp -= sizeof(ptlib->stack);
	regs.r_esp &= -16UL;
	if (ptrace_write(pid, regs.r_esp, ptlib->stack, sizeof(ptlib->stack)) != sizeof(ptlib->stack))
		goto FREE_REGS_EXIT;

	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		goto FREE_REGS_EXIT;

	if (ptrace_read(pid, regs.r_eip, *orig_code, shellcode_size) != shellcode_size)
		goto FREE_EXIT;

	if (ptrace(PT_SETREGS, pid, (caddr_t)&regs, 0) == -1)
		goto FREE_EXIT;

	if (ptrace_write(pid, regs.r_eip, shellcode, shellcode_size) == 0)
		goto CLEAN_EXIT;

	goto EXIT;
CLEAN_EXIT:
	ptrace(PT_SETREGS, pid, (caddr_t)*orig_regs, 0);
FREE_EXIT:
	free(*orig_code);
FREE_REGS_EXIT:
	free(*orig_regs);
	shellcode_size = 0;
EXIT:
	return shellcode_size;
}

void
ptrace_restore_libcall(pid_t pid, void *orig_regs, void *orig_code, size_t shellcode_size)
{
	struct reg *pregs = (struct reg *)orig_regs;

	assert(orig_regs != NULL && orig_code != NULL && shellcode_size > 0);

	ptrace(PT_SETREGS, pid, (caddr_t)pregs, 0);
	ptrace_write(pid, pregs->r_eip, orig_code, shellcode_size);

	free(orig_regs);
	free(orig_code);
}

long
ptrace_get_libcall_ret(pid_t pid)
{
	long ret;
	struct reg regs;

	errno = 0;

	ret = ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0);
	if (ret != -1) {
		ret = regs.r_eax;
	}

	return ret;
}
