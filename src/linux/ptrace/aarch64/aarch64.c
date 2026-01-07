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
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <asm/ptrace.h>
#include <linux/elf.h>
#include <memory.h>

static int
ptrace_getregs(pid_t pid, struct user_pt_regs *regs)
{
	struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
	return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
}

static int
ptrace_setregs(pid_t pid, struct user_pt_regs *regs)
{
	struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

long
ptrace_get_syscall_ret(pid_t pid)
{
	struct user_pt_regs regs;
	if (ptrace_getregs(pid, &regs) == -1)
		return -1;
	return regs.regs[0];
}

size_t
ptrace_setup_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys, void **orig_regs, void **orig_code)
{
	static const char shellcode[] = { 0x01, 0x00, 0x00, 0xD4 }; /* svc #0 */
	struct user_pt_regs regs;
	size_t shellcode_size = sizeof(shellcode);

	assert((bits == 32 || bits == 64) && ptsys != NULL && orig_regs != NULL && *orig_regs == NULL && orig_code != NULL && *orig_code == NULL);

	if (ptrace_getregs(pid, &regs) == -1)
		return 0;

	*orig_regs = malloc(sizeof(regs));
	if (*orig_regs == NULL)
		return 0;

	*(struct user_pt_regs *)(*orig_regs) = regs;

	/* Setup registers */
	regs.regs[8] = ptsys->syscall_num;
	regs.regs[0] = ptsys->args[0];
	regs.regs[1] = ptsys->args[1];
	regs.regs[2] = ptsys->args[2];
	regs.regs[3] = ptsys->args[3];
	regs.regs[4] = ptsys->args[4];
	regs.regs[5] = ptsys->args[5];

	/* Backup original code to restore later */
	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		goto FREE_REGS_EXIT;

	if (ptrace_read(pid, regs.pc, *orig_code, shellcode_size) != shellcode_size)
		goto FREE_EXIT;

	if (ptrace_setregs(pid, &regs) == -1)
		goto FREE_EXIT;

	if (ptrace_write(pid, (long)regs.pc, shellcode, shellcode_size) == 0)
		goto CLEAN_EXIT;

	goto EXIT;
CLEAN_EXIT:
	ptrace_setregs(pid, (struct user_pt_regs *)(*orig_regs));
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
	struct user_pt_regs *pregs = (struct user_pt_regs *)orig_regs;

	assert(orig_regs != NULL && orig_code != NULL && shellcode_size > 0);

	ptrace_setregs(pid, pregs);
	ptrace_write(pid, pregs->pc, orig_code, shellcode_size);

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
		/* BLR x17 */
		0x20, 0x02, 0x3F, 0xD6,
		/* BRK #0 */
		0x00, 0x00, 0x20, 0xD4
	};
	size_t shellcode_size = sizeof(shellcode);
	struct user_pt_regs regs;
	size_t i;

	assert((bits == 32 || bits == 64) && ptlib && orig_regs && orig_code);

	if (ptrace_getregs(pid, &regs) == -1)
		return 0;

	*orig_regs = malloc(sizeof(regs));
	if (*orig_regs == NULL)
		return 0;
	**(struct user_pt_regs **)orig_regs = regs;

	/* Setup stack */
	regs.regs[17] = ptlib->address;
	regs.sp -= sizeof(ptlib->stack);
	regs.sp &= -16UL;
	if (ptrace_write(pid, regs.sp, ptlib->stack, sizeof(ptlib->stack)) != sizeof(ptlib->stack))
		goto FREE_REGS_EXIT;

	/* Setup register arguments */
	regs.regs[0] = ptlib->args[0];
	regs.regs[1] = ptlib->args[1];
	regs.regs[2] = ptlib->args[2];
	regs.regs[3] = ptlib->args[3];
	regs.regs[4] = ptlib->args[4];
	regs.regs[5] = ptlib->args[5];

	*orig_code = malloc(shellcode_size);
	if (*orig_code == NULL)
		goto FREE_REGS_EXIT;

	if (ptrace_read(pid, regs.pc, *orig_code, shellcode_size) != shellcode_size)
		goto FREE_EXIT;

	if (ptrace_setregs(pid, &regs) == -1)
		goto FREE_EXIT;

	if (ptrace_write(pid, regs.pc, shellcode, shellcode_size) == 0)
		goto CLEAN_EXIT;

	goto EXIT;
CLEAN_EXIT:
	ptrace_setregs(pid, (struct user_pt_regs *)(*orig_regs));
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
	struct user_pt_regs *pregs = (struct user_pt_regs *)orig_regs;

	assert(orig_regs != NULL && orig_code != NULL && shellcode_size > 0);

	ptrace_setregs(pid, pregs);
	ptrace_write(pid, pregs->pc, orig_code, shellcode_size);

	free(orig_regs);
	free(orig_code);
}

long
ptrace_get_libcall_ret(pid_t pid)
{
	struct user_pt_regs regs;
	if (ptrace_getregs(pid, &regs) == -1)
		return -1;
	return regs.regs[0];
}
