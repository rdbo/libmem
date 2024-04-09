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
	return ptrace(PTRACE_PEEKUSER, pid, RAX * sizeof(long), NULL);
}

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

	/* Backup original code to restore later */
	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		goto FREE_REGS_EXIT;

	if (ptrace_read(pid, regs.rip, *orig_code, shellcode_size) != shellcode_size)
		goto FREE_EXIT;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
		goto FREE_EXIT;

	if (ptrace_write(pid, (long)regs.rip, shellcode, shellcode_size) == 0)
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
		ptsys.syscall_num = 90; /* x86_32 mmap syscall number */
	} else {
		ptsys.syscall_num = SYS_mmap;
	}

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

	if (bits == 32)
		ptsys.syscall_num = 91; /* x86_32 munmap syscall number */
	else
		ptsys.syscall_num = SYS_munmap;

	ptsys.args[0] = alloc; /* `void *addr` */
	ptsys.args[1] = size;  /* `size_t length` */

	return ptrace_syscall(pid, bits, &ptsys);
}

long
ptrace_mprotect(pid_t pid, size_t bits, long addr, size_t size, int prot)
{
	ptrace_syscall_t ptsys;

	if (bits == 32)
		ptsys.syscall_num = 125; /* x86_32 mprotect syscall number */
	else
		ptsys.syscall_num = SYS_mprotect;

	ptsys.args[0] = addr;
	ptsys.args[1] = size;
	ptsys.args[2] = prot;

	return ptrace_syscall(pid, bits, &ptsys);
}

size_t
ptrace_setup_libcall(pid_t pid, size_t bits, ptrace_libcall_t *ptlib, void **orig_regs, void **orig_code)
{
	uint8_t *shellcode;
	size_t shellcode_size = 0;
	struct user_regs_struct regs;

	assert((bits == 32 || bits == 64) && ptlib && orig_regs && orig_code);

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		return 0;

	*orig_regs = malloc(sizeof(regs));
	if (*orig_regs == NULL)
		return 0;
	**(struct user_regs_struct **)orig_regs = regs;

	if (bits == 64) {
		static const uint8_t shellcode64[] = {
			0x57, 0x56,
			/* call rax */
			0xFF, 0xD0,
			/* int3 */
			0xCC
		};
		shellcode_size = sizeof(shellcode64);
		shellcode = (uint8_t *)alloca(shellcode_size);
		memcpy(shellcode, shellcode64, shellcode_size);

		regs.rax = ptlib->address;
		regs.rdi = ptlib->args[0];
		regs.rsi = ptlib->args[1];
		regs.rdx = ptlib->args[2];
		regs.rcx = ptlib->args[3];
		regs.r8 = ptlib->args[4];
		regs.r9 = ptlib->args[5];
		regs.rsp &= -16UL;
	} else {
		/* TODO: Don't push, write directly on the aligned stack instead */
		static const uint8_t shellcode32[] = {
			/* push eax */
			0x50,
			/* push ebx */
			0x53,
			/* push ecx */
			0x51,
			/* push edx */
			0x52,
			/* push esi */
			0x56,
			/* push edi */
			0x57,
			/* call <address> */
			0xE8, 0x00, 0x00, 0x00, 0x00,
			/* int3 */
			0xCC
		};
		size_t i;

		shellcode_size = sizeof(shellcode32);
		shellcode = (uint8_t *)alloca(shellcode_size);
		memcpy(shellcode, shellcode32, shellcode_size);
		*(uint32_t *)&shellcode[7] = (uint32_t)(ptlib->address - regs.rip - 5);

		regs.rax = ptlib->args[0];
		regs.rbx = ptlib->args[1];
		regs.rcx = ptlib->args[2];
		regs.rdx = ptlib->args[3];
		regs.rsi = ptlib->args[4];
		regs.rdi = ptlib->args[5];
		regs.rsp &= -16UL;

		/* Prevent unused args from being pushed */
		for (i = ARRLEN(ptlib->args) - 1; i >= ptlib->num_args; --i) {
			shellcode[i] = 0x90;
		}
	}

	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		goto FREE_REGS_EXIT;

	if (ptrace_read(pid, regs.rip, *orig_code, shellcode_size) != shellcode_size)
		goto FREE_EXIT;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
		goto FREE_EXIT;

	if (ptrace_write(pid, regs.rip, shellcode, shellcode_size) == 0)
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
	ptrace_write(pid, pregs->rip, orig_code, shellcode_size);

	free(orig_regs);
	free(orig_code);
}

long
ptrace_get_libcall_ret(pid_t pid)
{
	errno = 0;
	return ptrace(PTRACE_PEEKUSER, pid, RAX * sizeof(long), NULL);
}
