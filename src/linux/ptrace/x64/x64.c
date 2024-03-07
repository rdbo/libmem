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
#include <stdlib.h>
#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/mman.h>

long
ptrace_get_syscall_ret(pid_t pid)
{
	errno = 0;
	return ptrace(PTRACE_PEEKUSER, pid, ORIG_RAX * sizeof(long), NULL);
}

/* NOTE: If this function fails and `*orig_code` is not NULL, you must restore the state of the target process */
size_t
ptrace_setup_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys, void **orig_regs, void **orig_code)
{
	static const char shellcode32[] = { 0xcd, 0x80 };
	static const char shellcode64[] = { 0x0f, 0x05 };
	struct user_regs_struct regs;
	char *shellcode;
	size_t shellcode_size = 0;

	assert((bits == 64 || bits == 32) && ptsys != NULL && orig_regs != NULL && *orig_regs == NULL && orig_code != NULL && *orig_code == NULL);

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		return 0;

	*orig_regs = malloc(sizeof(regs));
	if (*orig_regs == NULL)
		return 0;
	*(struct user_regs_struct *)(*orig_regs) = regs;

	/* Setup registers */
	regs.rax = ptsys->syscall_num;
	if (bits == 64) {
		regs.rdi = ptsys->args[0];
		regs.rsi = ptsys->args[1];
		regs.rdx = ptsys->args[2];
		regs.r10 = ptsys->args[3];
		regs.r8 = ptsys->args[4];
		regs.r9 = ptsys->args[5];
		shellcode = (char *)shellcode64;
		shellcode_size = sizeof(shellcode64);
	} else {
		regs.rbx = ptsys->args[0];
		regs.rcx = ptsys->args[1];
		regs.rdx = ptsys->args[2];
		regs.rsi = ptsys->args[3];
		regs.rdi = ptsys->args[4];
		regs.rbp = ptsys->args[5];
		shellcode = (char *)shellcode32;
		shellcode_size = sizeof(shellcode32);
	}
	regs.rsp = (regs.rsp - shellcode_size) & -16;

	/* Backup original code to restore later */
	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		return 0;
	if (ptrace_read(pid, regs.rip, *orig_code, shellcode_size) != shellcode_size) {
		free(*orig_code);
		*orig_code = NULL;
		return 0;
	}
	
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
		return 0;

	shellcode_size = ptrace_write(pid, (long)regs.rsp, shellcode, shellcode_size);
	return shellcode_size;
}

void
ptrace_restore_syscall(pid_t pid, void *orig_regs, void *orig_code, size_t shellcode_size)
{
	struct user_regs_struct *pregs = (struct user_regs_struct *)orig_regs;
	struct user_regs_struct regs;

	assert(orig_regs != NULL && orig_code != NULL && shellcode_size > 0);

	ptrace(PTRACE_SETREGS, pid, NULL, pregs);
	ptrace_write(pid, pregs->rip, orig_code, shellcode_size);

	free(orig_regs);
	free(orig_code);
}

long
ptrace_alloc(pid_t pid, size_t bits, size_t size, int prot)
{
	long alloc;
	ptrace_syscall_t ptsys;
	
	if (bits == 32) {
		ptsys.syscall_num = 192; /* mmap2 syscall number */
	} else {
		ptsys.syscall_num = SYS_mmap;
	}

	/* Setup mmap arguments */
	ptsys.args[0] = 0;    /* `void *addr` */
	ptsys.args[1] = size; /* `size_t length` */
	ptsys.args[2] = prot; /* `int prot` */
	ptsys.args[3] = 0;    /* `int flags` */
	ptsys.args[4] = -1L;  /* `int fd` */
	ptsys.args[5] = 0;    /* `off_t offset` */

	alloc = ptrace_syscall(pid, bits, &ptsys);
	/* NOTE: Testing if `alloc <= 0x100` is useful to avoid weird values, like 0x23 */
	if (alloc == -1 && errno || (void *)alloc == MAP_FAILED || alloc <= 0x100)
		alloc = -1;

	return alloc;
}
