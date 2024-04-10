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

#define ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))

long
ptrace_get_syscall_ret(pid_t pid)
{
	errno = 0;
	return ptrace(PTRACE_PEEKUSER, pid, EAX * sizeof(long), NULL);
}

size_t
ptrace_setup_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys, void **orig_regs, void **orig_code)
{
	static const char shellcode[] = { 0xcd, 0x80 };
	struct user_regs_struct regs;
	size_t shellcode_size = sizeof(shellcode);

	assert((bits == 64 || bits == 32) && ptsys != NULL && orig_regs != NULL && *orig_regs == NULL && orig_code != NULL && *orig_code == NULL);

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		return 0;

	*orig_regs = malloc(sizeof(regs));
	if (*orig_regs == NULL)
		return 0;

	*(struct user_regs_struct *)(*orig_regs) = regs;

	/* Setup registers */
	regs.eax = ptsys->syscall_num;
	regs.ebx = ptsys->args[0];
	regs.ecx = ptsys->args[1];
	regs.edx = ptsys->args[2];
	regs.esi = ptsys->args[3];
	regs.edi = ptsys->args[4];
	regs.ebp = ptsys->args[5];

	/* Backup original code to restore later */
	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		goto FREE_REGS_EXIT;

	if (ptrace_read(pid, regs.eip, *orig_code, shellcode_size) != shellcode_size)
		goto FREE_EXIT;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
		goto FREE_EXIT;

	if (ptrace_write(pid, (long)regs.eip, shellcode, shellcode_size) == 0)
		goto CLEAN_EXIT;

	goto EXIT;
CLEAN_EXIT:
	ptrace(PTRACE_SETREGS, pid, NULL, orig_regs);
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
	struct user_regs_struct *pregs = (struct user_regs_struct *)orig_regs;

	assert(orig_regs != NULL && orig_code != NULL && shellcode_size > 0);

	ptrace(PTRACE_SETREGS, pid, NULL, pregs);
	ptrace_write(pid, pregs->eip, orig_code, shellcode_size);

	free(orig_regs);
	free(orig_code);
}

long
ptrace_alloc(pid_t pid, size_t bits, size_t size, int prot)
{
	long alloc;
	ptrace_syscall_t ptsys;
	
	ptsys.syscall_num = SYS_mmap2;

	/* Setup mmap arguments */
	ptsys.args[0] = 0;                      /* `void *addr` */
	ptsys.args[1] = size;                   /* `size_t length` */
	ptsys.args[2] = prot;                   /* `int prot` */
	ptsys.args[3] = MAP_PRIVATE | MAP_ANON; /* `int flags` */
	ptsys.args[4] = -1;                     /* `int fd` */
	ptsys.args[5] = 0;                      /* `off_t offset` */

	alloc = ptrace_syscall(pid, bits, &ptsys);
	if (alloc == -1 && errno || (void *)alloc == MAP_FAILED)
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

	return ptrace_syscall(pid, bits, &ptsys);
}

size_t
ptrace_setup_libcall(pid_t pid, size_t bits, ptrace_libcall_t *ptlib, void **orig_regs, void **orig_code)
{
	const uint8_t shellcode[] = {
		/* call eax */
		0xFF, 0xD0,
		/* int3 */
		0xCC
	};
	size_t shellcode_size = sizeof(shellcode);
	struct user_regs_struct regs;
	size_t i;

	assert((bits == 32 || bits == 64) && ptlib && orig_regs && orig_code);

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		return 0;

	*orig_regs = malloc(sizeof(regs));
	if (*orig_regs == NULL)
		return 0;
	**(struct user_regs_struct **)orig_regs = regs;

	/* Setup stack */
	regs.eax = ptlib->address;
	regs.esp -= sizeof(ptlib->stack);
	regs.esp &= -16UL;
	if (ptrace_write(pid, regs.esp, ptlib->stack, sizeof(ptlib->stack)) != sizeof(ptlib->stack))
		goto FREE_REGS_EXIT;

	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		goto FREE_REGS_EXIT;

	if (ptrace_read(pid, regs.eip, *orig_code, shellcode_size) != shellcode_size)
		goto FREE_EXIT;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
		goto FREE_EXIT;

	if (ptrace_write(pid, regs.eip, shellcode, shellcode_size) == 0)
		goto CLEAN_EXIT;

	goto EXIT;
CLEAN_EXIT:
	ptrace(PTRACE_SETREGS, pid, NULL, orig_regs);
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
	struct user_regs_struct *pregs = (struct user_regs_struct *)orig_regs;

	assert(orig_regs != NULL && orig_code != NULL && shellcode_size > 0);

	ptrace(PTRACE_SETREGS, pid, NULL, pregs);
	ptrace_write(pid, pregs->eip, orig_code, shellcode_size);

	free(orig_regs);
	free(orig_code);
}

long
ptrace_get_libcall_ret(pid_t pid)
{
	errno = 0;
	return ptrace(PTRACE_PEEKUSER, pid, EAX * sizeof(long), NULL);
}
