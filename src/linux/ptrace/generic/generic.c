/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2025    Rdbo
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
#include <errno.h>

long
ptrace_get_syscall_ret(pid_t pid)
{
	errno = ENOSYS;
	return -1;
}

size_t
ptrace_setup_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys, void **orig_regs, void **orig_code)
{
	errno = ENOSYS;
	return 0;
}

void
ptrace_restore_syscall(pid_t pid, void *orig_regs, void *orig_code, size_t shellcode_size)
{
	errno = ENOSYS;
	return;
}

long
ptrace_alloc(pid_t pid, size_t bits, size_t size, int prot)
{
	errno = ENOSYS;
	return -1;
}

long
ptrace_free(pid_t pid, size_t bits, long alloc, size_t size)
{
	errno = ENOSYS;
	return -1;
}

long
ptrace_mprotect(pid_t pid, size_t bits, long addr, size_t size, int prot)
{
	errno = ENOSYS;
	return -1;
}

size_t
ptrace_setup_libcall(pid_t pid, size_t bits, ptrace_libcall_t *ptlib, void **orig_regs, void **orig_code)
{
	errno = ENOSYS;
	return -1;
}

void
ptrace_restore_libcall(pid_t pid, void *orig_regs, void *orig_code, size_t shellcode_size)
{
	errno = ENOSYS;
	return;
}

long
ptrace_get_libcall_ret(pid_t pid)
{
	errno = ENOSYS;
	return -1;
}
