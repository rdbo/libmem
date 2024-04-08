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

#include "ptrace.h"
#include <stdlib.h>
#include <memory.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <errno.h>

int
ptrace_attach(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
		return -1;

	waitpid(pid, NULL, 0);
	return 0;
}

size_t
ptrace_read(pid_t pid, long src, char *dst, size_t size)
{
	size_t bytes_read;
	long data;
	const size_t data_size = sizeof(data);
	size_t read_diff;
	size_t diff;

	for (bytes_read = 0; bytes_read < size; bytes_read += read_diff) {
		diff = size - bytes_read;

		errno = 0;
		data = ptrace(PTRACE_PEEKDATA, pid, src + bytes_read, NULL);
		if (data == -1 && errno)
			break;
		
		if (diff >= data_size) {
			read_diff = data_size;
		} else {
			read_diff = diff;
		}

		memcpy(&dst[bytes_read], &data, read_diff);
	}

	return bytes_read;
}

size_t
ptrace_write(pid_t pid, long dst, const char *src, size_t size)
{
	size_t bytes_written;
	long data;
	const size_t data_size = sizeof(data);
	size_t write_diff;
	size_t diff;
	long destaddr;

	for (bytes_written = 0; bytes_written < size; bytes_written += write_diff) {
		diff = size - bytes_written;
		destaddr = dst + bytes_written;
		if (diff >= data_size) {
			write_diff = data_size;
		} else {
			/* Read missing aligned bytes for a ptrace write into the 
			 * data before writing */
			errno = 0;
			data = ptrace(PTRACE_PEEKDATA, pid, destaddr, NULL);
			if (data == -1 && errno)
				break;

			write_diff = diff;
		}
		memcpy(&data, &src[bytes_written], write_diff);
		
		if (ptrace(PTRACE_POKEDATA, pid, destaddr, data))
			break;
	}

	return bytes_written;
}

#include <sys/user.h>
#include <stdio.h>
void
dump_registers(pid_t pid)
{
	struct user_regs_struct regs;
	
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
		return;

	printf("rax: %lx\nrbx: %lx\nrcx: %lx\nrdx: %lx\nrsi: %lx\nrdi: %lx\nrbp: %lx\nrsp: %lx\nrip: %lx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp, regs.rsp, regs.rip);
}

long
ptrace_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys)
{
	long alloc = -1;
	void *orig_regs = NULL;
	void *orig_code = NULL;
	size_t shellcode_size;

	/* Write shellcode and setup regs */
	if ((shellcode_size = ptrace_setup_syscall(pid, bits, ptsys, &orig_regs, &orig_code)) == 0) {
		if (orig_code)
			goto RESTORE_EXIT;
		if (orig_regs)
			free(orig_regs);
		return alloc;
	}

	/* Step to system call */
	printf("PRE-SYSCALL REGS:\n");
	dump_registers(pid);

	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	waitpid(pid, NULL, 0);

	/* Run system call */
	ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
	waitpid(pid, NULL, 0);

	printf("POST-SYSCALL REGS:\n");
	dump_registers(pid);

	/* Restore program state prior to syscall */
	alloc = ptrace_get_syscall_ret(pid);
RESTORE_EXIT:
	ptrace_restore_syscall(pid, orig_regs, orig_code, shellcode_size);
	return alloc;
}

void
ptrace_detach(pid_t pid)
{
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
