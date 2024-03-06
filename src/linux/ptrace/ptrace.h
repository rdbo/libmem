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

typedef struct {
	int syscall_num;
	long args[6];
} ptrace_syscall_t;

int
ptrace_attach(pid_t pid);

size_t
ptrace_read(pid_t pid, long src, char *dst, size_t size);

size_t
ptrace_write(pid_t pid, long dst, char *src, size_t size);

long
ptrace_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys);

void
ptrace_detach(pid_t pid);

void
ptrace_free_regs(void *regs);

/* Architecture-specific functions */
void *
ptrace_get_regs(pid_t pid);

long
ptrace_get_pc(void *regs);

long
ptrace_get_syscall_ret(pid_t pid);

size_t
ptrace_setup_syscall(pid_t pid, size_t bits, long shellcode_addr, ptrace_syscall_t *ptsys);

void
ptrace_restore_syscall(pid_t pid, void *orig_regs, size_t shellcode_size);

#endif
