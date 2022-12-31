#include "internal.h"

/*
 * System call and library call interfacing with Assembly (Linux):
 * https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux
 */

#if LM_OS != LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_PtraceAttach(lm_pid_t pid)
{
	int status;

#	if LM_OS == LM_OS_LINUX
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
#	if LM_OS == LM_OS_LINUX
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
#	else
	ptrace(PT_DETACH, pid, (caddr_t)NULL, 0);
#	endif
}

LM_PRIVATE lm_size_t
_LM_PtraceGetRegs(lm_pid_t pid, lm_void_t **regsbuf)
{
#	if LM_OS == LM_OS_LINUX
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

#	if LM_OS == LM_OS_LINUX
	struct user_regs_struct *pregs = (struct user_regs_struct *)regs;
#		if LM_BITS == 64
	program_counter = pregs->rip;
#		else
	program_counter = pregs->eip;
#		endif
#	else
	struct reg *pregs = (struct user_regs_struct *)regs;
#		if LM_BITS == 64
	program_counter = pregs->r_rip;
#		else
	program_counter = pregs->r_eip;
#		endif
#	endif

	return program_counter;
}

LM_PRIVATE lm_void_t
_LM_SetupSyscallRegs(_lm_syscall_data_t *data,
		     lm_size_t           bits,
		     lm_void_t          *regs,
		     lm_uintptr_t       *program_counter)
{
#	if LM_OS == LM_OS_LINUX
	struct user_regs_struct *pregs = (struct user_regs_struct *)regs;
#		if LM_BITS == 64
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
#		else
	pregs->eax = data->syscall_num;
	pregs->ebx = data->arg0;
	pregs->ecx = data->arg1;
	pregs->edx = data->arg2;
	pregs->esi = data->arg3;
	pregs->edi = data->arg4;
	pregs->ebp = data->arg5;
#		endif
#	else
	struct reg *pregs = (struct reg *)regs;
#		if LM_BITS == 64
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
#		else
	pregs->r_eax = data->syscall_num;
	pregs->r_ebx = data->arg0;
	pregs->r_ecx = data->arg1;
	pregs->r_edx = data->arg2;
	pregs->r_esi = data->arg3;
	pregs->r_edi = data->arg4;
	pregs->r_ebp = data->arg5;
#		endif
#	endif

	*program_counter = _LM_GetProgramCounter(regs);
}

LM_PRIVATE lm_bool_t
_LM_PtraceSetRegs(lm_pid_t pid, lm_void_t *regs)
{
#	if LM_OS == LM_OS_LINUX
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
		dst[i] = (lm_byte_t)ptrace(PTRACE_PEEKDATA,
					   pid,
					   (void *)LM_OFFSET(src, i),
					   NULL);

		if (dst[i] == (lm_byte_t)-1 && errno)
			return LM_FALSE;
	}
#	elif LM_OS == LM_OS_BSD
	for (i = 0; i < size; ++i) {
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
		if (ptrace(PTRACE_POKEDATA, pid, (void *)LM_OFFSET(dst, i),
			   *(lm_uintptr_t *)(&buf[i])) == -1)
			goto FREE_RET;
	}
#	elif LM_OS == LM_OS_BSD
	for (i = 0; i < aligned_size; i += sizeof(lm_uintptr_t)) {
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

#	if LM_OS == LM_OS_LINUX
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
_LM_GenerateSyscall(lm_size_t bits, lm_byte_t **pcodebuf)
{
	if (bits == 64)
		return LM_AssembleEx("syscall", LM_ARCH, bits, LM_NULLPTR, pcodebuf);

	return LM_AssembleEx("int 80", LM_ARCH, bits, LM_NULLPTR, pcodebuf);
}

LM_PRIVATE lm_uintptr_t
_LM_GetSyscallRet(lm_void_t *regs)
{
	lm_uintptr_t ret = 0;
#	if LM_OS == LM_OS_LINUX
#		if LM_BITS == 64
	ret = ((struct user_regs_struct *)regs)->rax;
#		else
	ret = ((struct user_regs_struct *)regs)->eax;
#		endif
#	else
#		if LM_BITS == 64
	ret = ((struct reg *)regs)->r_rax;
#		else
	ret = ((struct reg *)regs)->r_eax;
#		endif
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
	lm_byte_t   *codebuf;
	lm_size_t    codesize;
	lm_void_t   *regs = LM_NULLPTR;
	lm_void_t   *old_regs = LM_NULLPTR;
	lm_uintptr_t program_counter;
	lm_size_t    bits;
	lm_byte_t   *old_code;
	
	LM_ASSERT(pproc != LM_NULLPTR && data != LM_NULLPTR);

	codesize = _LM_GenerateSyscall(pproc->bits, &codebuf);
	if (!codesize)
		return ret;

	old_code = LM_MALLOC(codesize);
	if (!old_code)
		goto FREE_CODEBUF_RET;


	if (!_LM_PtraceAttach(pid))
		goto FREE_OLDCODE_RET;

	/* save original registers and a copy that will be modified
	   for the injection */
	if (!_LM_PtraceGetRegs(pid, &old_regs) ||
	    !_LM_PtraceGetRegs(pid, &regs))
		goto DETACH_RET;
	
	/* setup injection registers and get the program counter,
	   which is where the code will be injected */
	_LM_SetupSyscallRegs(data, bits, regs, &program_counter);

	/* save original code in a buffer and write the payload */
	if (!_LM_PtraceRead(pid, program_counter, old_code, codesize) ||
	    !_LM_PtraceWrite(pid, program_counter, codebuf, codesize))
		goto FREE_REGS_RET;

	/* (debugging) check if the right payload was written */
	/* _LM_PtraceRead(pid, program_counter, codebuf, codesize); */

	/* write the new registers and step a single instruction */
	_LM_PtraceSetRegs(pid, regs);
	_LM_PtraceStep(pid);

	/* save registers after running the system call and retrieve
	   its return value */
	_LM_PtraceGetRegs(pid, &regs);
	if (syscall_ret)
		*syscall_ret = _LM_GetSyscallRet(regs);

	/* write the original code and registers */
	_LM_PtraceWrite(pid, program_counter, old_code, codesize);
	_LM_PtraceSetRegs(pid, old_regs);

	/* (debugging) check if the right original code was written */
	/* _LM_PtraceRead(pid, program_counter, codebuf, codesize); */

	/* if the program counter of regs and old regs is the same,
	   the syscall has not executed */
	ret = _LM_CheckProgramCounter(regs, old_regs);
FREE_REGS_RET:
	_LM_PtraceFreeRegs(&old_regs);
	_LM_PtraceFreeRegs(&regs);
DETACH_RET:
	_LM_PtraceDetach(pid); /* detach and continue process */
FREE_OLDCODE_RET:
	LM_FREE(old_code);
FREE_CODEBUF_RET:
	LM_FreeCodeBuffer(&codebuf);

	return ret;
}

typedef struct {
	regex_t     regex;
	lm_module_t libc_mod;
} _lm_find_libc_t;

LM_PRIVATE lm_bool_t
_LM_FindLibcCallback(lm_module_t *pmod,
		     lm_tstring_t path,
		     lm_void_t   *arg)
{
	_lm_find_libc_t *parg = (_lm_find_libc_t *)arg;

	if (!regexec(&parg->regex, path, 0, NULL, 0)) {
		parg->libc_mod = *pmod;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_FindLibc(lm_process_t *pproc,
	     lm_module_t  *libc_mod)
{
	_lm_find_libc_t arg;

	if (regcomp(&arg.regex, ".*/libc[\.\-].*", REG_EXTENDED))
		return LM_FALSE;

	/* (debugging) using patched version of dlopen that has been LD_PRELOAD'ed.
	   This version will just print the path and the flags so we know it has
	   been called properly */
	//if (regcomp(&arg.regex, ".*/modlibc[\.\-].*", REG_EXTENDED))
	//	return LM_FALSE;

	arg.libc_mod.size = 0;

	LM_EnumModulesEx(pproc, _LM_FindLibcCallback, (lm_void_t *)&arg);

	regfree(&arg.regex);

	if (arg.libc_mod.size <= 0)
		return LM_FALSE;

	*libc_mod = arg.libc_mod;

	return LM_TRUE;
}

LM_PRIVATE lm_size_t
_LM_GenerateLibcall(lm_size_t   bits,
		    lm_size_t   nargs,
		    lm_byte_t **pcodebuf)
{
	lm_char_t code[255];

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

	return LM_AssembleEx(code, LM_ARCH, bits, LM_NULLPTR, pcodebuf);
}

LM_PRIVATE lm_void_t
_LM_SetupLibcallRegs(_lm_libcall_data_t *data,
		     lm_size_t           bits,
		     lm_void_t          *regs,
		     lm_uintptr_t       *program_counter)
{
#	if LM_OS == LM_OS_LINUX
	struct user_regs_struct *pregs = (struct user_regs_struct *)regs;
#		if LM_BITS == 64
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
#		else
	pregs->eax = data->func_addr;
	pregs->ebx = data->arg0;
	pregs->ecx = data->arg1;
	pregs->edx = data->arg2;
	pregs->esi = data->arg3;
	pregs->edi = data->arg4;
	/* pregs->ebp = data->arg5; */
#		endif
#	else
	struct reg *pregs = (struct reg *)regs;
#		if LM_BITS == 64
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
#		else
	pregs->r_eax = data->func_addr;
	pregs->r_ebx = data->arg0;
	pregs->r_ecx = data->arg1;
	pregs->r_edx = data->arg2;
	pregs->r_esi = data->arg3;
	pregs->r_edi = data->arg4;
	/* pregs->r_ebp = data->arg5; */
#		endif
#	endif

	*program_counter = _LM_GetProgramCounter(regs);
}

LM_PRIVATE lm_uintptr_t
_LM_GetLibcallRet(lm_void_t *regs)
{
	lm_uintptr_t ret = 0;
#	if LM_OS == LM_OS_LINUX
#		if LM_BITS == 64
	ret = ((struct user_regs_struct *)regs)->rax;
#		else
	ret = ((struct user_regs_struct *)regs)->eax;
#		endif
#	else
#		if LM_BITS == 64
	ret = ((struct reg *)regs)->r_rax;
#		else
	ret = ((struct reg *)regs)->r_eax;
#		endif
#	endif
	return ret;
}

LM_PRIVATE lm_bool_t
_LM_PtraceContAndWait(lm_pid_t pid)
{
	int status;

#	if LM_OS == LM_OS_LINUX
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
	lm_byte_t   *codebuf;
	lm_size_t    codesize;
	lm_void_t   *regs = LM_NULLPTR;
	lm_void_t   *old_regs = LM_NULLPTR;
	lm_uintptr_t program_counter;
	lm_size_t    bits;
	lm_byte_t   *old_code;
	
	LM_ASSERT(pid != LM_PID_BAD && data != LM_NULLPTR);

	bits = LM_GetProcessBitsEx(pid);

	codesize = _LM_GenerateLibcall(bits, data->nargs, &codebuf);
	if (!codesize)
		return ret;

	old_code = LM_MALLOC(codesize);
	if (!old_code)
		goto FREE_CODEBUF_RET;


	if (!_LM_PtraceAttach(pid))
		goto FREE_OLDCODE_RET;

	/* save original registers and a copy that will be modified
	   for the injection */
	if (!_LM_PtraceGetRegs(pid, &old_regs) ||
	    !_LM_PtraceGetRegs(pid, &regs))
		goto DETACH_RET;
	
	/* setup injection registers and get the program counter,
	   which is where the code will be injected */
	_LM_SetupLibcallRegs(data, bits, regs, &program_counter);

	/* save original code in a buffer and write the payload */
	if (!_LM_PtraceRead(pid, program_counter, old_code, codesize) ||
	    !_LM_PtraceWrite(pid, program_counter, codebuf, codesize))
		goto FREE_REGS_RET;

	/* (debugging) check if the right payload was written */
	/* _LM_PtraceRead(pid, program_counter, codebuf, codesize); */

	/* write the new registers and continue the process,
	   waiting for it to SIGINT */
	_LM_PtraceSetRegs(pid, regs);
	_LM_PtraceContAndWait(pid);

	/* save registers after running the system call and retrieve
	   its return value */
	_LM_PtraceGetRegs(pid, &regs);
	if (call_ret)
		*call_ret = _LM_GetLibcallRet(regs);

	/* write the original code and registers */
	_LM_PtraceWrite(pid, program_counter, old_code, codesize);
	_LM_PtraceSetRegs(pid, old_regs);

	/* (debugging) check if the right original code was written */
	/* _LM_PtraceRead(pid, program_counter, codebuf, codesize); */

	/* if the program counter of regs and old regs is the same,
	   the syscall has not executed */
	ret = _LM_CheckProgramCounter(regs, old_regs);
FREE_REGS_RET:
	_LM_PtraceFreeRegs(&old_regs);
	_LM_PtraceFreeRegs(&regs);
DETACH_RET:
	_LM_PtraceDetach(pid); /* detach and continue process */
FREE_OLDCODE_RET:
	LM_FREE(old_code);
FREE_CODEBUF_RET:
	LM_FreeCodeBuffer(&codebuf);

	return ret;

}

LM_PRIVATE lm_bool_t
_LM_CallDlopen(lm_process_t *pproc,
	       lm_tstring_t  path,
	       lm_int_t      mode,
	       void        **plibhandle)
{
	lm_bool_t          ret = LM_FALSE;
	lm_module_t        libc_mod;
	lm_address_t       dlopen_addr;
	lm_size_t          modpath_size;
	lm_address_t       modpath_addr;
	_lm_libcall_data_t data;
	lm_uintptr_t       modhandle = 0;

	if (!_LM_FindLibc(pproc, &libc_mod))
		return ret;

	dlopen_addr = LM_FindSymbolEx(pproc, &libc_mod, "__libc_dlopen_mode");
	if (dlopen_addr == LM_ADDRESS_BAD) {
		dlopen_addr = LM_FindSymbolEx(pproc, &libc_mod, "dlopen");
		if (dlopen_addr == LM_ADDRESS_BAD)
			return ret;
	}

	/* it is LM_STRLEN(path) + 1 because the null terminator should also be written */
	modpath_size = (LM_STRLEN(path) + 1) * sizeof(lm_tchar_t);
	modpath_addr = LM_AllocMemoryEx(pproc, modpath_size, LM_PROT_XRW);
	if (modpath_addr == LM_ADDRESS_BAD)
		return ret;

	if (!LM_WriteMemoryEx(pproc, modpath_addr, path, modpath_size))
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
	lm_module_t        libc_mod;
	lm_address_t       dlclose_addr;
	_lm_libcall_data_t data;
	lm_uintptr_t       retval;

	if (!_LM_FindLibc(pproc, &libc_mod))
		return ret;

	dlclose_addr = LM_FindSymbolEx(pproc, &libc_mod, "__libc_dlclose");
	if (dlclose_addr == LM_ADDRESS_BAD) {
		dlclose_addr = LM_FindSymbolEx(pproc, &libc_mod, "dlclose");
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
#endif

