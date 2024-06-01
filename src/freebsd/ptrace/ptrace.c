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
	if (ptrace(PT_ATTACH, pid, 0, 0) == -1)
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
		data = ptrace(PT_READ_D, pid, (caddr_t)(src + bytes_read), 0);
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
			data = ptrace(PT_READ_D, pid, (caddr_t)destaddr, 0);
			if (data == -1 && errno)
				break;

			write_diff = diff;
		}
		memcpy(&data, &src[bytes_written], write_diff);
		
		if (ptrace(PT_WRITE_D, pid, (caddr_t)destaddr, data))
			break;
	}

	return bytes_written;
}

#ifndef NDEBUG
#	define DEBUG 1
#endif

#ifdef DEBUG
void
DBG_dump_info(pid_t pid)
{
	struct reg regs;
	char stack[256];
	long result;
	size_t i;

	result = ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0);
	printf("ptrace get regs result: %ld\n", result);
	printf("ptrace registers:\n");

#	if defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
	printf("\teax: %lx\n", (unsigned long)regs.r_eax);
	printf("\tebx: %lx\n", (unsigned long)regs.r_ebx);
	printf("\tecx: %lx\n", (unsigned long)regs.r_ecx);
	printf("\tedx: %lx\n", (unsigned long)regs.r_edx);
	printf("\tesi: %lx\n", (unsigned long)regs.r_esi);
	printf("\tedi: %lx\n", (unsigned long)regs.r_edi);
	printf("\tebp: %lx\n", (unsigned long)regs.r_ebp);
	printf("\tesp: %lx\n", (unsigned long)regs.r_esp);

	result = (long)ptrace_read(pid, regs.r_esp, stack, sizeof(stack));
#	elif defined(__x86_64__) || defined(_M_X64)
	printf("\trax: %lx\n", (unsigned long)regs.r_rax);
	printf("\trbx: %lx\n", (unsigned long)regs.r_rbx);
	printf("\trcx: %lx\n", (unsigned long)regs.r_rcx);
	printf("\trdx: %lx\n", (unsigned long)regs.r_rdx);
	printf("\trsi: %lx\n", (unsigned long)regs.r_rsi);
	printf("\trdi: %lx\n", (unsigned long)regs.r_rdi);
	printf("\trbp: %lx\n", (unsigned long)regs.r_rbp);
	printf("\trsp: %lx\n", (unsigned long)regs.r_rsp);
	printf("\tr8: %lx\n", (unsigned long)regs.r_r8);
	printf("\tr9 %lx\n", (unsigned long)regs.r_r9);
	printf("\tr10: %lx\n", (unsigned long)regs.r_r10);

	result = (long)ptrace_read(pid, regs.r_esp, stack, sizeof(stack));
#	endif
	printf("ptrace_read result: %ld\n", result);
	
	printf("stack dump: \n[ ");
	for (i = 0; i < sizeof(stack); i += sizeof(uint32_t)) {
		printf("%x ", *(uint32_t *)&stack[i]);
	}
	printf("]\n");
}
#endif

long
ptrace_syscall(pid_t pid, size_t bits, ptrace_syscall_t *ptsys)
{
	long ret = -1;
	void *orig_regs = NULL;
	void *orig_code = NULL;
	size_t shellcode_size;

#	ifdef DEBUG
	printf("[*] Original program state dump:\n");
	DBG_dump_info(pid);
	printf("--------------------------------\n");
#	endif

	/* Write shellcode and setup regs */
	if ((shellcode_size = ptrace_setup_syscall(pid, bits, ptsys, &orig_regs, &orig_code)) == 0)
		return ret;

#	ifdef DEBUG
	printf("[*] Pre-syscall dump:\n");
	DBG_dump_info(pid);
	printf("--------------------------------\n");
#	endif

	/* Step to system call */
	ptrace(PT_STEP, pid, 0, 0);
	waitpid(pid, NULL, 0);

	/* Get return value */
	ret = ptrace_get_syscall_ret(pid);

#	ifdef DEBUG
	printf("[*] Post-syscall dump:\n");
	DBG_dump_info(pid);
	printf("--------------------------------\n");
#	endif

	/* Restore program state prior to syscall */
	ptrace_restore_syscall(pid, orig_regs, orig_code, shellcode_size);

#	ifdef DEBUG
	printf("[*] Post-restore dump:\n");
	DBG_dump_info(pid);
	printf("--------------------------------\n");
#	endif
	return ret;
}

void
ptrace_detach(pid_t pid)
{
	ptrace(PT_DETACH, pid, 0, 0);
}

long
ptrace_libcall(pid_t pid, size_t bits, ptrace_libcall_t *ptlib)
{
	long ret = -1;
	void *orig_regs = NULL;
	void *orig_code = NULL;
	size_t shellcode_size;

	/* Write shellcode and setup regs */
	if ((shellcode_size = ptrace_setup_libcall(pid, bits, ptlib, &orig_regs, &orig_code)) == 0)
		return ret;

	/* Continue until a breakpoint is triggered */
	ptrace(PT_CONTINUE, pid, 0, 0);
	waitpid(pid, NULL, 0);

	/* Get return value */
	ret = ptrace_get_libcall_ret(pid);

	/* Restore program state prior to syscall */
	ptrace_restore_libcall(pid, orig_regs, orig_code, shellcode_size);
	return ret;
}
