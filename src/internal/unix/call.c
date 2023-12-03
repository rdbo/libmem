/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2022    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "internal.h"

/*
 * System call and library call interfacing with Assembly (Linux):
 * https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux
 */

LM_PRIVATE lm_bool_t
_LM_PtraceAttach(lm_pid_t pid)
{
	int status;

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
		return LM_FALSE;
#	else
	if (ptrace(PT_ATTACH, pid, NULL, 0) == -1)
		return LM_FALSE;
#	endif

	waitpid(pid, &status, WSTOPPED);
	return LM_TRUE;
}

LM_PRIVATE lm_void_t
_LM_PtraceDetach(lm_pid_t pid)
{
#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
#	else
	ptrace(PT_DETACH, pid, (caddr_t)NULL, 0);
#	endif
}

LM_PRIVATE lm_size_t
_LM_PtraceGetRegs(lm_pid_t pid, lm_void_t **regsbuf)
{
#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		return 0;
#	else
	struct reg regs;
	if (ptrace(PT_GETREGS, pid, (caddr_t)&regs, 0) == -1)
		return 0;
#	endif

	/* check if regsbuf has not been already alocated */
	if (!(*regsbuf)) {
		*regsbuf = LM_MALLOC(sizeof(regs));
		if (!(*regsbuf))
			return 0;
	}

	LM_MEMCPY(*regsbuf, &regs, sizeof(regs));

	return sizeof(regs);
}

LM_PRIVATE lm_void_t
_LM_PtraceFreeRegs(lm_void_t **regsbuf)
{
	if (*regsbuf)
		LM_FREE(*regsbuf);

	*regsbuf = LM_NULLPTR;
}

LM_PRIVATE lm_uintptr_t
_LM_GetProgramCounter(lm_void_t *regs)
{
	lm_uintptr_t program_counter = 0;

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	struct user_regs_struct *pregs = (struct user_regs_struct *)regs;
#		if LM_ARCH == LM_ARCH_ARM
#			if LM_BITS == 64
	program_counter = pregs->pc;
#			else
	/* TODO: Implement */
#			endif /* LM_BITS */
#		else
#			if LM_BITS == 64
	program_counter = pregs->rip;
#			else
	program_counter = pregs->eip;
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	else
	struct reg *pregs = (struct user_regs_struct *)regs;
#		if LM_ARCH == LM_ARCH_ARM
#			if LM_BITS == 64
	program_counter = pregs->uregs[15];
#			else
	/* TODO: Implement */
#			endif /* LM_BITS */
#		else
#			if LM_BITS == 64
	program_counter = pregs->r_rip;
#			else
	program_counter = pregs->r_eip;
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	endif

	return program_counter;
}

LM_PRIVATE lm_void_t
_LM_SetupSyscallRegs(_lm_syscall_data_t *data,
		     lm_size_t           bits,
		     lm_void_t          *regs,
		     lm_uintptr_t       *program_counter)
{
#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	struct user_regs_struct *pregs = (struct user_regs_struct *)regs;
#		if LM_ARCH == LM_ARCH_ARM
#			if LM_BITS == 64
	pregs->regs[8] = data->syscall_num;
	pregs->regs[0] = data->arg0;
	pregs->regs[1] = data->arg1;
	pregs->regs[2] = data->arg2;
	pregs->regs[3] = data->arg3;
	pregs->regs[4] = data->arg4;
	pregs->regs[5] = data->arg5;
#			else
	/* TODO: Implement */
#			endif /* LM_BITS */
#		else
#			if LM_BITS == 64
	/* target process bits is 64 */
	if (bits == 64) {
		pregs->rax = data->syscall_num;
		pregs->rdi = data->arg0;
		pregs->rsi = data->arg1;
		pregs->rdx = data->arg2;
		pregs->r10 = data->arg3;
		pregs->r8  = data->arg4;
		pregs->r9  = data->arg5;
	} else {
		pregs->rax = data->syscall_num;
		pregs->rbx = data->arg0;
		pregs->rcx = data->arg1;
		pregs->rdx = data->arg2;
		pregs->rsi = data->arg3;
		pregs->rdi = data->arg4;
		pregs->rbp = data->arg5;
	}
#			else
	pregs->eax = data->syscall_num;
	pregs->ebx = data->arg0;
	pregs->ecx = data->arg1;
	pregs->edx = data->arg2;
	pregs->esi = data->arg3;
	pregs->edi = data->arg4;
	pregs->ebp = data->arg5;
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	else
	struct reg *pregs = (struct reg *)regs;
#		if LM_ARCH == LM_ARCH_ARM
#			if LM_BITS == 64
	pregs->uregs[8] = data->syscall_num;
	pregs->uregs[0] = data->arg0;
	pregs->uregs[1] = data->arg1;
	pregs->uregs[2] = data->arg2;
	pregs->uregs[3] = data->arg3;
	pregs->uregs[4] = data->arg4;
	pregs->uregs[5] = data->arg5;
#			else
	/* TODO: Implement */
#			endif
#		else
#			if LM_BITS == 64
	/* target process bits is 64 */
	if (bits == 64) {
		pregs->r_rax = data->syscall_num;
		pregs->r_rdi = data->arg0;
		pregs->r_rsi = data->arg1;
		pregs->r_rdx = data->arg2;
		pregs->r_r10 = data->arg3;
		pregs->r_r8  = data->arg4;
		pregs->r_r9  = data->arg5;
	} else {
		pregs->r_rax = data->syscall_num;
		pregs->r_rbx = data->arg0;
		pregs->r_rcx = data->arg1;
		pregs->r_rdx = data->arg2;
		pregs->r_rsi = data->arg3;
		pregs->r_rdi = data->arg4;
		pregs->r_rbp = data->arg5;
	}
#			else
	pregs->r_eax = data->syscall_num;
	pregs->r_ebx = data->arg0;
	pregs->r_ecx = data->arg1;
	pregs->r_edx = data->arg2;
	pregs->r_esi = data->arg3;
	pregs->r_edi = data->arg4;
	pregs->r_ebp = data->arg5;
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	endif /* LM_OS */

	*program_counter = _LM_GetProgramCounter(regs);
}

LM_PRIVATE lm_bool_t
_LM_PtraceSetRegs(lm_pid_t pid, lm_void_t *regs)
{
#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1)
		return LM_FALSE;
#	else
	if (ptrace(PT_SETREGS, pid, (caddr_t)regs, 0) == -1)
		return LM_FALSE;
#	endif

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_PtraceRead(lm_pid_t     pid,
	       lm_uintptr_t src,
	       lm_byte_t   *dst,
	       lm_size_t    size)
{
	lm_size_t   i;

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	for (i = 0; i < size; ++i) {
		errno = 0;
		dst[i] = (lm_byte_t)ptrace(PTRACE_PEEKDATA,
					   pid,
					   (void *)LM_OFFSET(src, i),
					   NULL);

		if (dst[i] == (lm_byte_t)-1 && errno) {
			printf("errno: %d\n", errno);
		 	return LM_FALSE;
		}
	}
#	elif LM_OS == LM_OS_BSD
	for (i = 0; i < size; ++i) {
		errno = 0;
		dst[i] = (lm_byte_t)ptrace(PT_READ_D,
					   pid,
					   (caddr_t)LM_OFFSET(src, i),
					   0);
		if (dst[i] == (lm_byte_t)-1 && errno)
			return LM_FALSE;
	}
#	endif
	
	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_PtraceWrite(lm_pid_t     pid,
		lm_uintptr_t dst,
		lm_byte_t   *src,
		lm_size_t    size)
{
	lm_bool_t   ret = LM_FALSE;
	lm_size_t   i;
	lm_size_t   aligned_size = size;
	lm_byte_t  *buf;

	aligned_size += aligned_size > sizeof(lm_uintptr_t) ?
		aligned_size % sizeof(lm_uintptr_t) :
		sizeof(lm_uintptr_t) - aligned_size;
	
	buf = (lm_byte_t *)LM_CALLOC(aligned_size, sizeof(lm_byte_t));
	if (!buf)
		return ret;
	
	if (!_LM_PtraceRead(pid, dst, buf, aligned_size))
		goto FREE_RET;

	LM_MEMCPY(buf, src, size);

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	for (i = 0; i < aligned_size; i += sizeof(lm_uintptr_t)) {
		errno = 0;
		if (ptrace(PTRACE_POKEDATA, pid, (void *)LM_OFFSET(dst, i),
			   *(lm_uintptr_t *)(&buf[i])) == -1)
			goto FREE_RET;
	}
#	elif LM_OS == LM_OS_BSD
	for (i = 0; i < aligned_size; i += sizeof(lm_uintptr_t)) {
		errno = 0;
		if (ptrace(PT_WRITE_D, pid, (caddr_t)LM_OFFSET(dst, i),
			   *(lm_uintptr_t *)(&buf[i])) == -1)
			goto FREE_RET;
	}
#	endif

	ret = LM_TRUE;
FREE_RET:
	LM_FREE(buf);	
	return ret;
}

LM_PRIVATE lm_bool_t
_LM_PtraceStep(lm_pid_t pid)
{
	int status;

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
		return LM_FALSE;
#	else
	if (ptrace(PT_STEP, pid, (caddr_t)NULL, 0) == -1)
		return LM_FALSE;
#	endif
	waitpid(pid, &status, WSTOPPED);

	return LM_TRUE;
}

LM_PRIVATE lm_size_t
_LM_GenerateSyscall(lm_size_t bits, lm_bytearr_t *pcodebuf)
{
	if (bits == 64)
		return LM_AssembleEx("syscall", bits, LM_ADDRESS_BAD, pcodebuf);

	return LM_AssembleEx("int 80", bits, LM_ADDRESS_BAD, pcodebuf);
}

LM_PRIVATE lm_uintptr_t
_LM_GetSyscallRet(lm_void_t *regs)
{
	lm_uintptr_t ret = 0;
#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
#		if LM_ARCH == LM_ARCH_ARM
#			if LM_BITS == 64
	ret = ((struct user_regs_struct *)regs)->regs[0];
#			else
	/* TODO: Implement */
#			endif /* LM_BITS */
#		else
#			if LM_BITS == 64
	ret = ((struct user_regs_struct *)regs)->rax;
#			else
	ret = ((struct user_regs_struct *)regs)->eax;
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	else
#		if LM_ARCH == LM_ARCH_ARM
#			if LM_BITS == 64
	ret = ((struct user_regs_struct *)regs)->uregs[0];
#			else
	/* TODO: Implement */
#			endif /* LM_BITS */
#		else
#			if LM_BITS == 64
	ret = ((struct reg *)regs)->r_rax;
#			else
	ret = ((struct reg *)regs)->r_eax;
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	endif
	return ret;
}

LM_PRIVATE lm_bool_t
_LM_CheckProgramCounter(lm_void_t *regs, lm_void_t *old_regs)
{
	lm_uintptr_t pc;
	lm_uintptr_t old_pc;

	pc = _LM_GetProgramCounter(regs);
	old_pc = _LM_GetProgramCounter(old_regs);

	return pc == old_pc ? LM_FALSE : LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_SystemCallEx(lm_process_t       *pproc,
		 _lm_syscall_data_t *data,
		 lm_uintptr_t       *syscall_ret)
{
	lm_bool_t    ret = LM_FALSE;
	lm_bytearr_t codebuf;
	lm_size_t    codesize;
	lm_void_t   *regs = LM_NULLPTR;
	lm_void_t   *old_regs = LM_NULLPTR;
	lm_uintptr_t program_counter;
	lm_byte_t   *old_code;
	
	LM_ASSERT(pproc != LM_NULLPTR && data != LM_NULLPTR);

	codesize = _LM_GenerateSyscall(pproc->bits, &codebuf);
	if (!codesize)
		return ret;

	old_code = LM_MALLOC(codesize);
	if (!old_code)
		goto FREE_CODEBUF_RET;

	if (!_LM_PtraceAttach(pproc->pid))
		goto FREE_OLDCODE_RET;

	/* save original registers and a copy that will be modified
	   for the injection */
	if (!_LM_PtraceGetRegs(pproc->pid, &old_regs) ||
	    !_LM_PtraceGetRegs(pproc->pid, &regs))
		goto DETACH_RET;
	
	/* setup injection registers and get the program counter,
	   which is where the code will be injected */
	_LM_SetupSyscallRegs(data, pproc->bits, regs, &program_counter);

	/* save original code in a buffer and write the payload */
	if (!_LM_PtraceRead(pproc->pid, program_counter, old_code, codesize) ||
	    !_LM_PtraceWrite(pproc->pid, program_counter, codebuf, codesize))
		goto FREE_REGS_RET;

	/* (debugging) check if the right payload was written */
	/* _LM_PtraceRead(pproc->pid, program_counter, codebuf, codesize); */

	/* write the new registers and step a single instruction */
	_LM_PtraceSetRegs(pproc->pid, regs);
	_LM_PtraceStep(pproc->pid);

	/* save registers after running the system call and retrieve
	   its return value */
	_LM_PtraceGetRegs(pproc->pid, &regs);
	if (syscall_ret)
		*syscall_ret = _LM_GetSyscallRet(regs);

	/* write the original code and registers */
	_LM_PtraceWrite(pproc->pid, program_counter, old_code, codesize);
	_LM_PtraceSetRegs(pproc->pid, old_regs);

	/* (debugging) check if the right original code was written */
	/* _LM_PtraceRead(pproc->pid, program_counter, codebuf, codesize); */

	/* if the program counter of regs and old regs is the same,
	   the syscall has not executed */
	ret = _LM_CheckProgramCounter(regs, old_regs);
FREE_REGS_RET:
	_LM_PtraceFreeRegs(&old_regs);
	_LM_PtraceFreeRegs(&regs);
DETACH_RET:
	_LM_PtraceDetach(pproc->pid); /* detach and continue process */
FREE_OLDCODE_RET:
	LM_FREE(old_code);
FREE_CODEBUF_RET:
	LM_FreeCodeBuffer(codebuf);

	return ret;
}

typedef struct {
	regex_t     regex;
	lm_module_t lib_mod;
} _lm_find_lib_t;

LM_PRIVATE lm_bool_t
_LM_FindLibCallback(lm_module_t *pmod,
		    lm_void_t   *arg)
{
	_lm_find_lib_t *parg = (_lm_find_lib_t *)arg;

	if (!regexec(&parg->regex, pmod->path, 0, NULL, 0)) {
		parg->lib_mod = *pmod;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_FindLibc(lm_process_t *pproc,
	     lm_module_t  *lib_mod)
{
	_lm_find_lib_t arg;

	/* TODO: Improve regex. A folder named 'libc.so.1' would match */
	if (regcomp(&arg.regex, ".*/(libc[.-]|.*musl[.-]).*", REG_EXTENDED))
		return LM_FALSE;

	/* (debugging) using patched version of dlopen that has been LD_PRELOAD'ed.
	   This version will just print the path and the flags so we know it has
	   been called properly */
	//if (regcomp(&arg.regex, ".*/modlibc[\.\-].*", REG_EXTENDED))
	//	return LM_FALSE;

	arg.lib_mod.size = 0;

	LM_EnumModulesEx(pproc, _LM_FindLibCallback, (lm_void_t *)&arg);

	regfree(&arg.regex);

	if (arg.lib_mod.size <= 0)
		return LM_FALSE;

	*lib_mod = arg.lib_mod;

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_FindLibdl(lm_process_t *pproc,
	      lm_module_t  *lib_mod)
{
	_lm_find_lib_t arg;

	/* TODO: Improve regex. A folder named 'libdl.so.1' would match */
	if (regcomp(&arg.regex, ".*/libdl[.-].*", REG_EXTENDED))
		return LM_FALSE;

	arg.lib_mod.size = 0;

	LM_EnumModulesEx(pproc, _LM_FindLibCallback, (lm_void_t *)&arg);

	regfree(&arg.regex);

	if (arg.lib_mod.size <= 0)
		return LM_FALSE;

	*lib_mod = arg.lib_mod;

	return LM_TRUE;
}

LM_PRIVATE lm_size_t
_LM_GenerateLibcall(lm_size_t     bits,
		    lm_size_t     nargs,
		    lm_bytearr_t *pcodebuf)
{
	lm_cchar_t code[255];

	if (bits == 64) {
		/* single stepping won't work, because the call instruction
		   will only enter the function and not actually execute its
		   code. in other to break after the function has executed,
		   we need to insert an interrupt instruction after the call
		   so that the process gets interrupted (SIGINT) after the
		   function jumps back to the return address. EAX/RAX is not
		   used in a library call, so we'll put the function address
		   in it. */
		LM_CSNPRINTF(code, sizeof(code), "call rax ; int3");
	} else {
		lm_size_t i;
		lm_cstring_t push_list[] = {
			"push ebx ; ",
			"push ecx ; ",
			"push edx ; ",
			"push esi ; ",
			"push edi ; "
		};

		LM_ASSERT(nargs <= LM_ARRLEN(push_list));

		for (i = 0; i < nargs; ++i)
			LM_CSNPRINTF(code, sizeof(code), push_list[i]);

		LM_CSNPRINTF(code, sizeof(code), "call eax ; int3");
	}

	return LM_AssembleEx(code, bits, LM_ADDRESS_BAD, pcodebuf);
}

LM_PRIVATE lm_void_t
_LM_SetupLibcallRegs(_lm_libcall_data_t *data,
		     lm_size_t           bits,
		     lm_void_t          *regs,
		     lm_uintptr_t       *program_counter)
{
#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	struct user_regs_struct *pregs = (struct user_regs_struct *)regs;
#		if LM_ARCH == LM_ARCH_ARM
		/* TODO: Implement */
#		else
#			if LM_BITS == 64
	/* target process bits is 64 */
	if (bits == 64) {
		/*
		 * Arg0: rdi
		 * Arg1: rsi
		 * Arg2: rdx
		 * Arg3: rcx
		 * Arg4: r8
		 * Arg5: r9
		 * Ret:  rax
		 */
		pregs->rax = data->func_addr;
		pregs->rdi = data->arg0;
		pregs->rsi = data->arg1;
		pregs->rdx = data->arg2;
		pregs->rcx = data->arg3;
		pregs->r8  = data->arg4;
		pregs->r9  = data->arg5;
	} else {
		/*
		 * The registers don't matter,
		 * their values will be pushed
		 * onto the stack
		 */
		pregs->rax = data->func_addr;
		pregs->rbx = data->arg0;
		pregs->rcx = data->arg1;
		pregs->rdx = data->arg2;
		pregs->rsi = data->arg3;
		pregs->rdi = data->arg4;
		/* pregs->rbp = data->arg5; */
	}
#			else
	pregs->eax = data->func_addr;
	pregs->ebx = data->arg0;
	pregs->ecx = data->arg1;
	pregs->edx = data->arg2;
	pregs->esi = data->arg3;
	pregs->edi = data->arg4;
	/* pregs->ebp = data->arg5; */
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	else
	struct reg *pregs = (struct reg *)regs;
#		if LM_ARCH == LM_ARCH_ARM
	/* TODO: Implement */
#		else
#			if LM_BITS == 64
	/* target process bits is 64 */
	if (bits == 64) {
		pregs->r_rax = data->func_addr;
		pregs->r_rdi = data->arg0;
		pregs->r_rsi = data->arg1;
		pregs->r_rdx = data->arg2;
		pregs->r_rcx = data->arg3;
		pregs->r_r8  = data->arg4;
		pregs->r_r9  = data->arg5;
	} else {
		pregs->r_rax = data->func_addr;
		pregs->r_rbx = data->arg0;
		pregs->r_rcx = data->arg1;
		pregs->r_rdx = data->arg2;
		pregs->r_rsi = data->arg3;
		pregs->r_rdi = data->arg4;
		/* pregs->r_rbp = data->arg5; */
	}
#			else
	pregs->r_eax = data->func_addr;
	pregs->r_ebx = data->arg0;
	pregs->r_ecx = data->arg1;
	pregs->r_edx = data->arg2;
	pregs->r_esi = data->arg3;
	pregs->r_edi = data->arg4;
	/* pregs->r_ebp = data->arg5; */
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	endif

	*program_counter = _LM_GetProgramCounter(regs);
}

LM_PRIVATE lm_uintptr_t
_LM_GetLibcallRet(lm_void_t *regs)
{
	lm_uintptr_t ret = 0;
#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
#		if LM_ARCH == LM_ARCH_ARM
	/* TODO: Implement */
#		else
#			if LM_BITS == 64
	ret = ((struct user_regs_struct *)regs)->rax;
#			else
	ret = ((struct user_regs_struct *)regs)->eax;
#			endif /* LM_BITS */
#		endif /* LM_ARCH */
#	else
#		if LM_ARCH == LM_ARCH_ARM
	/* TODO: Implement */
#		else
#			if LM_BITS == 64
	ret = ((struct reg *)regs)->r_rax;
#			else
	ret = ((struct reg *)regs)->r_eax;
#			endif
#		endif
#	endif
	return ret;
}

LM_PRIVATE lm_bool_t
_LM_PtraceContAndWait(lm_pid_t pid)
{
	int status;

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
		return LM_FALSE;
#	else
	if (ptrace(PT_CONTINUE, pid, (caddr_t)NULL, 0) == -1)
		return LM_FALSE;
#	endif
	waitpid(pid, &status, WSTOPPED);

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_LibraryCallEx(lm_process_t      *pproc,
		 _lm_libcall_data_t *data,
		 lm_uintptr_t       *call_ret)
{
	lm_bool_t    ret = LM_FALSE;
	lm_bytearr_t codebuf;
	lm_size_t    codesize;
	lm_void_t   *regs = LM_NULLPTR;
	lm_void_t   *old_regs = LM_NULLPTR;
	lm_uintptr_t program_counter;
	lm_byte_t   *old_code;
	
	LM_ASSERT(pproc != LM_NULLPTR && data != LM_NULLPTR);

	codesize = _LM_GenerateLibcall(pproc->bits, data->nargs, &codebuf);
	if (!codesize)
		return ret;

	old_code = LM_MALLOC(codesize);
	if (!old_code)
		goto FREE_CODEBUF_RET;


	if (!_LM_PtraceAttach(pproc->pid))
		goto FREE_OLDCODE_RET;

	/* save original registers and a copy that will be modified
	   for the injection */
	if (!_LM_PtraceGetRegs(pproc->pid, &old_regs) ||
	    !_LM_PtraceGetRegs(pproc->pid, &regs))
		goto DETACH_RET;
	
	/* setup injection registers and get the program counter,
	   which is where the code will be injected */
	_LM_SetupLibcallRegs(data, pproc->bits, regs, &program_counter);

	/* save original code in a buffer and write the payload */
	if (!_LM_PtraceRead(pproc->pid, program_counter, old_code, codesize) ||
	    !_LM_PtraceWrite(pproc->pid, program_counter, codebuf, codesize))
		goto FREE_REGS_RET;

	/* (debugging) check if the right payload was written */
	/* _LM_PtraceRead(pproc->pid, program_counter, codebuf, codesize); */

	/* write the new registers and continue the process,
	   waiting for it to SIGINT */
	_LM_PtraceSetRegs(pproc->pid, regs);
	_LM_PtraceContAndWait(pproc->pid);

	/* save registers after running the system call and retrieve
	   its return value */
	_LM_PtraceGetRegs(pproc->pid, &regs);
	if (call_ret)
		*call_ret = _LM_GetLibcallRet(regs);

	/* write the original code and registers */
	_LM_PtraceWrite(pproc->pid, program_counter, old_code, codesize);
	_LM_PtraceSetRegs(pproc->pid, old_regs);

	/* (debugging) check if the right original code was written */
	/* _LM_PtraceRead(pproc->pid, program_counter, codebuf, codesize); */

	/* if the program counter of regs and old regs is the same,
	   the syscall has not executed */
	ret = _LM_CheckProgramCounter(regs, old_regs);
FREE_REGS_RET:
	_LM_PtraceFreeRegs(&old_regs);
	_LM_PtraceFreeRegs(&regs);
DETACH_RET:
	_LM_PtraceDetach(pproc->pid); /* detach and continue process */
FREE_OLDCODE_RET:
	LM_FREE(old_code);
FREE_CODEBUF_RET:
	LM_FreeCodeBuffer(codebuf);

	return ret;

}

LM_PRIVATE lm_bool_t
_LM_CallDlopen(lm_process_t *pproc,
	       lm_string_t   path,
	       lm_int_t      mode,
	       void        **plibhandle)
{
	lm_bool_t          ret = LM_FALSE;
	lm_module_t        lib_mod;
	lm_address_t       dlopen_addr;
	lm_size_t          modpath_size;
	lm_address_t       modpath_addr;
	_lm_libcall_data_t data;
	lm_uintptr_t       modhandle = 0;

	if (!_LM_FindLibdl(pproc, &lib_mod) && !_LM_FindLibc(pproc, &lib_mod))
		return ret;

	dlopen_addr = LM_FindSymbolAddress(&lib_mod, "__libc_dlopen_mode");
	if (dlopen_addr == LM_ADDRESS_BAD) {
		dlopen_addr = LM_FindSymbolAddress(&lib_mod, "dlopen");
		if (dlopen_addr == LM_ADDRESS_BAD)
			return ret;
	}

	/* it is LM_STRLEN(path) + 1 because the null terminator should also be written */
	modpath_size = (LM_STRLEN(path) + 1) * sizeof(lm_char_t);
	modpath_addr = LM_AllocMemoryEx(pproc, modpath_size, LM_PROT_XRW);
	if (modpath_addr == LM_ADDRESS_BAD)
		return ret;

	if (!LM_WriteMemoryEx(pproc, modpath_addr, (lm_bytearr_t)path, modpath_size))
		goto FREE_RET;

	data.func_addr = (lm_uintptr_t)dlopen_addr;
	data.nargs = 2;
	data.arg0 = (lm_uintptr_t)modpath_addr;
	data.arg1 = (lm_uintptr_t)mode;
	data.arg2 = data.arg3 = data.arg4 = data.arg5 = 0;

	ret = _LM_LibraryCallEx(pproc, &data, &modhandle);
	if (!modhandle)
		ret = LM_FALSE;
	else if (plibhandle)
		*plibhandle = (void *)modhandle;
FREE_RET:
	LM_FreeMemoryEx(pproc, modpath_addr, modpath_size);
	return ret;

}

LM_PRIVATE lm_bool_t
_LM_CallDlclose(lm_process_t *pproc,
		void         *modhandle)
{
	lm_bool_t          ret = LM_FALSE;
	lm_module_t        lib_mod;
	lm_address_t       dlclose_addr;
	_lm_libcall_data_t data;
	lm_uintptr_t       retval;

	if (!_LM_FindLibdl(pproc, &lib_mod) && !_LM_FindLibc(pproc, &lib_mod))
		return ret;

	dlclose_addr = LM_FindSymbolAddress(&lib_mod, "__libc_dlclose");
	if (dlclose_addr == LM_ADDRESS_BAD) {
		dlclose_addr = LM_FindSymbolAddress(&lib_mod, "dlclose");
		if (dlclose_addr == LM_ADDRESS_BAD)
			return ret;
	}

	data.func_addr = (lm_uintptr_t)dlclose_addr;
	data.nargs = 1;
	data.arg0 = (lm_uintptr_t)modhandle;
	data.arg1 = data.arg2 = data.arg3 = data.arg4 = data.arg5 = 0;

	ret = _LM_LibraryCallEx(pproc, &data, &retval);
	if (retval)
		ret = LM_FALSE;

	return ret;
}
