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
#include <assert.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>

void *
ptrace_get_regs(pid_t pid)
{
	struct user_regs_struct *pregs;

	pregs = (struct user_regs_struct *)malloc(sizeof(*pregs));
	if (!pregs)
		return NULL;

	if (ptrace(PTRACE_GETREGS, pid, NULL, pregs) == -1) {
		free(pregs);
		pregs = NULL;
	}

	return pregs;
}

long
ptrace_get_pc(void *regs)
{
	struct user_regs_struct *pregs = (struct user_regs_struct *)regs;

	assert(pregs != NULL);

	return (long)pregs->rip;
}

long
ptrace_get_syscall_ret(pid_t pid)
{
	errno = 0;
	return ptrace(PTRACE_PEEKUSER, pid, ORIG_RAX * sizeof(long), NULL);
}

/* TODO: Do better clean up in target process if function fails */
size_t
ptrace_setup_syscall(pid_t pid, size_t bits, long shellcode_addr, ptrace_syscall_t *ptsys)
{
	static const char shellcode32[] = { 0xcd, 0x80 };
	static const char shellcode64[] = { 0x0f, 0x05 };
	struct user_regs_struct regs;
	char *shellcode;
	size_t shellcode_size = 0;
	char *orig_code;

	assert((bits == 64 || bits == 32) && ptsys != NULL);

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		return 0;

	/* Setup registers */
	regs.rax = ptsys->syscall_num;
	regs.rip = shellcode_addr;
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
		shellcode_size = sizeof(shellcode64);
	}
	regs.rsp = (regs.rsp - shellcode_size) & -16;
	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
		return 0;

	/* Backup original code in the stack to restore later */
	orig_code = (char *)malloc(shellcode_size);
	if (!orig_code)
		return 0;

	if (ptrace_read(pid, shellcode_addr, orig_code, shellcode_size) != shellcode_size) {
		shellcode_size = 0;
		goto FREE_EXIT;
	}

	shellcode_size = ptrace_write(pid, (long)regs.rsp, shellcode, shellcode_size);
FREE_EXIT:
	free(orig_code);
	return shellcode_size;
}

void
ptrace_restore_syscall(pid_t pid, void *orig_regs, size_t shellcode_size)
{
	struct user_regs_struct *pregs = (struct user_regs_struct *)orig_regs;
	struct user_regs_struct regs;
	char *orig_code;

	assert(orig_regs != NULL && shellcode_size > 0);

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		return;

	orig_code = (char *)malloc(shellcode_size);
	if (!orig_code)
		return;

	ptrace_read(pid, regs.rsp, orig_code, shellcode_size);
	ptrace(PTRACE_SETREGS, pid, NULL, orig_regs);
	ptrace_write(pid, pregs->rip, orig_code, shellcode_size);
	free(orig_code);
}
