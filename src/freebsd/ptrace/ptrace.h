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

#ifndef PTRACE_H
#define PTRACE_H

#include <unistd.h>

#define ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))

typedef struct {
	int syscall_num;
	long args[6];
	unsigned char stack[256];
} ptrace_syscall_t;

typedef struct {
	long address;
	long args[6];
	unsigned char stack[256];
} ptrace_libcall_t;

int
ptrace_attach(pid_t pid);

size_t
ptrace_read(pid_t pid, long src, char *dst, size_t size);

size_t
ptrace_write(pid_t pid, long dst, const char *src, size_t size);

long
ptrace_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys);

void
ptrace_detach(pid_t pid);

/* Architecture-specific functions */
long
ptrace_get_syscall_ret(pid_t pid);

size_t
ptrace_setup_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys, void **orig_regs, void **orig_code);

void
ptrace_restore_syscall(pid_t pid, void *orig_regs, void *orig_code, size_t shellcode_size);

long
ptrace_alloc(pid_t pid, size_t bits, size_t size, int prot);

long
ptrace_free(pid_t pid, size_t bits, long alloc, size_t size);

long
ptrace_mprotect(pid_t pid, size_t bits, long addr, size_t size, int prot);

size_t
ptrace_setup_libcall(pid_t pid, size_t bits, ptrace_libcall_t *ptlib, void **orig_regs, void **orig_code);

long
ptrace_libcall(pid_t pid, size_t bits, ptrace_libcall_t *ptlib);

void
ptrace_restore_libcall(pid_t pid, void *orig_regs, void *orig_code, size_t shellcode_size);

long
ptrace_get_libcall_ret(pid_t pid);

#endif
