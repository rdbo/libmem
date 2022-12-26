#include "internal.h"

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
	if (ptrace(PT_GETREGS, process.pid, (caddr_t)&regs, 0) == -1)
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
_LM_SetupRegs(_lm_syscall_data_t *data,
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
	/* tdata->arget process bits is 64 */
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
_LM_GeneratePayload(lm_size_t bits, lm_byte_t **pcodebuf)
{
	if (bits == 64)
		return LM_AssembleEx("syscall", LM_ARCH, bits, LM_NULLPTR, pcodebuf);

	return LM_AssembleEx("int80", LM_ARCH, bits, LM_NULLPTR, pcodebuf);
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
_LM_SystemCallEx(lm_process_t        proc,
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
	
	LM_ASSERT(LM_VALID_PROCESS(proc) && data != LM_NULLPTR);

	bits = LM_GetProcessBitsEx(proc);

	codesize = _LM_GeneratePayload(bits, &codebuf);
	if (!codesize)
		return ret;

	old_code = LM_MALLOC(codesize);
	if (!old_code)
		goto FREE_CODEBUF_RET;


	if (!_LM_PtraceAttach(proc.pid))
		goto FREE_OLDCODE_RET;

	/* save original registers and a copy that will be modified
	   for the injection */
	if (!_LM_PtraceGetRegs(proc.pid, &old_regs) ||
	    !_LM_PtraceGetRegs(proc.pid, &regs))
		goto DETACH_RET;
	
	/* setup injection registers and get the program counter,
	   which is where the code will be injected */
	_LM_SetupRegs(data, bits, regs, &program_counter);

	/* save original code in a buffer and write the payload */
	if (!_LM_PtraceRead(proc.pid, program_counter, old_code, codesize) ||
	    !_LM_PtraceWrite(proc.pid, program_counter, codebuf, codesize))
		goto FREE_REGS_RET;

	/* (debugging) check if the right payload was written */
	_LM_PtraceRead(proc.pid, program_counter, codebuf, codesize); 

	/* write the new registers and step a single instruction */
	_LM_PtraceSetRegs(proc.pid, regs);
	_LM_PtraceStep(proc.pid);

	/* save registers after running the system call and retrieve
	   its return value */
	_LM_PtraceGetRegs(proc.pid, &regs);
	if (syscall_ret)
		*syscall_ret = _LM_GetSyscallRet(regs);

	/* write the original code and registers */
	_LM_PtraceWrite(proc.pid, program_counter, old_code, codesize);
	_LM_PtraceSetRegs(proc.pid, old_regs);

	/* (debugging) check if the right original code was written */
	_LM_PtraceRead(proc.pid, program_counter, codebuf, codesize);

	/* if the program counter of regs and old regs is the same,
	   the syscall has not executed */
	ret = _LM_CheckProgramCounter(regs, old_regs);
FREE_REGS_RET:
	_LM_PtraceFreeRegs(&old_regs);
	_LM_PtraceFreeRegs(&regs);
DETACH_RET:
	_LM_PtraceDetach(proc.pid); /* detach and continue process */
FREE_OLDCODE_RET:
	LM_FREE(old_code);
FREE_CODEBUF_RET:
	LM_FreeCodeBuffer(&codebuf);

	return ret;
}
#endif

