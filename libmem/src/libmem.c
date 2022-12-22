/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

#include <libmem.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "helpers.c"
#if LM_OS == LM_OS_WIN
#	include "peparser.c"
#else
#	include "elfparser.c"
#endif
#include "process.c"
#include "thread.c"
#include "module.c"
#include "symbols.c"
#include "page.c"
#include "memory.c"
#include "scan.c"

#if LM_COMPATIBLE
/* Helpers */
static lm_size_t
_LM_DetourPayload(lm_address_t src,
		  lm_address_t dst,
		  lm_detour_t  detour,
		  lm_size_t    bits,
		  lm_byte_t  **buf)
{
	lm_size_t  size = 0;

	if (!buf)
		return size;

#	if LM_ARCH == LM_ARCH_X86
	switch (detour) {
	case LM_DETOUR_JMP32:
	{
		lm_byte_t payload[] = {
			0xE9, 0x0, 0x0, 0x0, 0x0 /* jmp 0x0 */
		};

		size = sizeof(payload);

		*(lm_uint32_t *)&payload[1] = (lm_uint32_t)(
			(lm_uintptr_t)dst - (lm_uintptr_t)src - size
		);

		*buf = (lm_byte_t *)LM_MALLOC(size);
		LM_MEMCPY(*buf, payload, size);
		break;
	}
	case LM_DETOUR_JMP64:
	case LM_DETOUR_ANY:
	{
		if (bits == 64) {
			lm_byte_t payload[] = {
			     0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, /* jmp [rip] */
			     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uintptr_t *)&payload[6] = (lm_uintptr_t)dst;

			*buf = (lm_byte_t *)LM_MALLOC(size);
			LM_MEMCPY(*buf, payload, size);	
		} else {
			lm_byte_t payload[] = {
				0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, /* jmp [eip] */
				0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uint32_t *)&payload[6] = (lm_uint32_t)(
				(lm_uintptr_t)dst
			);

			*buf = (lm_byte_t *)LM_MALLOC(size);
			LM_MEMCPY(*buf, payload, size);	
		}
		break;
	}
	case LM_DETOUR_CALL32:
	{
		lm_byte_t payload[] = {
			0xE8, 0x0, 0x0, 0x0, 0x0 /* call 0x0 */
		};

		size = sizeof(payload);

		*(lm_uint32_t *)&payload[1] = (lm_uint32_t)(
			(lm_uintptr_t)dst - (lm_uintptr_t)src - size
		);

		*buf = (lm_byte_t *)LM_MALLOC(size);
		LM_MEMCPY(*buf, payload, size);
		break;
	}
	case LM_DETOUR_CALL64:
	{
		if (bits == 64) {
			lm_byte_t payload[] = {
			     0xFF, 0x15, 0x0, 0x0, 0x0, 0x0, /* call [rip] */
			     0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uintptr_t *)&payload[6] = (lm_uintptr_t)dst;

			*buf = (lm_byte_t *)LM_MALLOC(size);
			LM_MEMCPY(*buf, payload, size);	
		} else {
			lm_byte_t payload[] = {
			       0xFF, 0x15, 0x0, 0x0, 0x0, 0x0, /* call [eip] */
			       0x0, 0x0, 0x0, 0x0 /* <dst> */
			};

			size = sizeof(payload);

			*(lm_uint32_t *)&payload[6] = (lm_uint32_t)(
				(lm_uintptr_t)dst
			);

			*buf = (lm_byte_t *)LM_MALLOC(size);
			LM_MEMCPY(*buf, payload, size);	
		}
		break;
	}
	case LM_DETOUR_RET32:
	{
		break;
	}
	case LM_DETOUR_RET64:
	{
		break;
	}
	}
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	return size;
}

static lm_void_t
_LM_ParseDatArgsIn(lm_process_t proc,
		   lm_datio_t  *datargs,
		   lm_size_t    nargs,
		   lm_size_t    stack_align,
		   lm_regs_t   *regsbuf)
{
	lm_size_t i;

	for (i = 0; i < nargs; ++i) {
#		if LM_ARCH == LM_ARCH_X86
		if (datargs[i].datloc != LM_DATLOC_STACK) {
			lm_void_t *reg;

			reg = LM_DebugPickReg(datargs[i].datloc, regsbuf);
			if (reg) {
#				if LM_OS == LM_OS_WIN
				if (LM_GetProcessBitsEx(proc) == 64) {
					*(lm_uintptr_t *)reg = (
						*(lm_uintptr_t *)(
							datargs[i].data
						)
					);
				} else {
					*(lm_uint32_t *)reg = (
						*(lm_uint32_t *)(
							datargs[i].data
						)
					);
				}
#				else
				*(lm_uintptr_t *)reg = (
					*(lm_uintptr_t *)(
						datargs[i].data
					)
				);
#				endif
			}
		} else {
			lm_void_t   *stack_ptr;
			lm_address_t dst;

#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64)
				stack_ptr = LM_DebugPickReg(LM_DATLOC_RSP, regsbuf);
			else
				stack_ptr = LM_DebugPickReg(LM_DATLOC_ESP, regsbuf);
#			else
			stack_ptr = LM_DebugPickReg(LM_DATLOC_ESP, regsbuf);
#			endif

#			if LM_OS == LM_OS_WIN
			if (LM_GetProcessBitsEx(proc) == 64) {
				*(lm_uintptr_t *)stack_ptr -= datargs[i].size;
				*(lm_uintptr_t *)stack_ptr &= stack_align;
				dst = (lm_address_t)(
					*(lm_uintptr_t *)stack_ptr
				);
			} else {
				*(lm_uint32_t *)stack_ptr -= datargs[i].size;
				*(lm_uint32_t *)stack_ptr &= stack_align;
				dst = (lm_address_t)(
					(lm_uintptr_t)(
						*(lm_uint32_t *)stack_ptr
					)
				);
			}
#			else
			*(lm_uintptr_t *)stack_ptr -= datargs[i].size;
			*(lm_uintptr_t *)stack_ptr &= stack_align;
			dst = (lm_address_t)(
				*(lm_uintptr_t *)stack_ptr
			);
#			endif

			LM_DebugWrite(proc, dst,
				      datargs[i].data, datargs[i].size);
		}
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
}

static lm_void_t
_LM_ParseDatArgsOut(lm_process_t proc,
		    lm_datio_t  *datargs,
		    lm_size_t    nargs,
		    lm_size_t    stack_align,
		    lm_regs_t    regs)
{
	lm_size_t i;

	for (i = 0; i < nargs; ++i) {
#		if LM_ARCH == LM_ARCH_X86
		if (datargs[i].datloc != LM_DATLOC_STACK) {
			lm_void_t *reg;

			reg = LM_DebugPickReg(datargs[i].datloc, &regs);
			if (reg) {
#				if LM_OS == LM_OS_WIN
				if (LM_GetProcessBitsEx(proc) == 64) {
					*(lm_uintptr_t *)datargs[i].data = (
						*(lm_uintptr_t *)reg
					);
				} else {
					*(lm_uintptr_t *)datargs[i].data = (
						(lm_uintptr_t)(
							*(lm_uint32_t *)reg
						)
					);
				}
#				else
				*(lm_uintptr_t *)datargs[i].data = (
					*(lm_uintptr_t *)reg
				);
#				endif
			}
		} else {
			lm_void_t   *stack_ptr;
			lm_address_t src;

#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64)
				stack_ptr = LM_DebugPickReg(LM_DATLOC_RSP, &regs);
			else
				stack_ptr = LM_DebugPickReg(LM_DATLOC_ESP, &regs);
#			else
			stack_ptr = LM_DebugPickReg(LM_DATLOC_ESP, &regs);
#			endif

#			if LM_OS == LM_OS_WIN
			if (LM_GetProcessBitsEx(proc) == 64) {
				src = (lm_address_t)(
					*(lm_uintptr_t *)stack_ptr
				);

				*(lm_uintptr_t *)stack_ptr += datargs[i].size;
				*(lm_uintptr_t *)stack_ptr += (
					datargs[i].size - 
					       (datargs[i].size & stack_align)
				);
			} else {
				src = (lm_address_t)(
					*(lm_uintptr_t *)stack_ptr
				);

				*(lm_uint32_t *)stack_ptr += datargs[i].size;
				*(lm_uint32_t *)stack_ptr += (
					datargs[i].size - 
					       (datargs[i].size & stack_align)
				);
			}
#			else
			src = (lm_address_t)(
				*(lm_uintptr_t *)stack_ptr
			);

			*(lm_uintptr_t *)stack_ptr += datargs[i].size;
			*(lm_uintptr_t *)stack_ptr += (
				datargs[i].size - 
					(datargs[i].size & stack_align)
			);
#			endif

			LM_DebugRead(proc, src,
				     datargs[i].data, datargs[i].size);
		}
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
}

LM_API lm_bool_t
_LM_DebugInject(lm_process_t proc,
		lm_bstring_t payload,
		lm_size_t    size,
		lm_regs_t    regs,
		lm_regs_t   *post_regs,
		lm_bool_t  (*run_func)(lm_process_t proc))
{
	lm_bool_t    ret = LM_FALSE;
	lm_address_t inj_addr;
	lm_byte_t   *old_code = (lm_byte_t *)LM_NULL;
	lm_regs_t    old_regs;

	old_code = (lm_byte_t *)LM_MALLOC(size);
	if (!old_code)
		return ret;

	LM_DebugGetRegs(proc, &old_regs);

#	if LM_ARCH == LM_ARCH_X86
#	if LM_BITS == 64
	if (LM_GetProcessBitsEx(proc) == 64) {
		inj_addr = (lm_address_t)LM_DebugReadReg(LM_DATLOC_RIP, regs);
	} else {
		inj_addr = (lm_address_t)LM_DebugReadReg(LM_DATLOC_EIP, regs);
	}
#	else
	inj_addr = (lm_address_t)LM_DebugReadReg(LM_DATLOC_EIP, regs);
#	endif
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	LM_DebugRead(proc, inj_addr, old_code, size);	
	LM_DebugWrite(proc, inj_addr, payload, size);
	LM_DebugSetRegs(proc, regs);
	run_func(proc);
	LM_DebugWaitProcess(proc);
	if (post_regs)
		LM_DebugGetRegs(proc, post_regs);
	LM_DebugWrite(proc, inj_addr, old_code, size);
	LM_DebugSetRegs(proc, old_regs);

	ret = LM_TRUE;
	LM_FREE(old_code);

	return ret;
}

#if LM_OS == LM_OS_WIN
#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
static lm_bool_t
_LM_PtraceRead(lm_process_t proc,
	       lm_address_t src,
	       lm_byte_t   *dst,
	       lm_size_t    size)
{
	lm_bool_t   ret = LM_FALSE;
	lm_size_t   i;

	if (!dst || !size)
		return ret;

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	for (i = 0; i < size; ++i) {
		dst[i] = (lm_byte_t)ptrace(PTRACE_PEEKDATA,
					   proc.pid,
					   (void *)(
						   &((lm_byte_t *)src)[i]
					   ),
					   NULL);
	}
#	elif LM_OS == LM_OS_BSD
	for (i = 0; i < size; ++i) {
		dst[i] = (lm_byte_t)ptrace(PT_READ_D,
					   proc.pid,
					   (caddr_t)(
						   &((lm_byte_t *)src)[i]
					   ),
					   0);
	}
#	endif
	
	ret = LM_TRUE;
	return ret;
}

static lm_bool_t
_LM_PtraceWrite(lm_process_t proc,
		lm_address_t dst,
		lm_byte_t   *src,
		lm_size_t    size)
{
	lm_bool_t   ret = LM_FALSE;
	lm_size_t   i;
	lm_size_t   aligned_size = size;
	lm_byte_t  *buf;

	if (!src || !size)
		return ret;
	
	aligned_size += aligned_size > sizeof(lm_uintptr_t) ?
		aligned_size % sizeof(lm_uintptr_t) :
		sizeof(lm_uintptr_t) - aligned_size;
	
	buf = (lm_byte_t *)LM_CALLOC(aligned_size, sizeof(lm_byte_t));
	if (!buf)
		return ret;
	
	_LM_PtraceRead(proc, dst, buf, aligned_size);
	LM_MEMCPY(buf, src, size);

#	if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	for (i = 0; i < aligned_size; i += sizeof(lm_uintptr_t)) {
		ptrace(PTRACE_POKEDATA,
		       proc.pid,
		       (void *)(&((lm_byte_t *)dst)[i]),
		       *(lm_uintptr_t *)(&buf[i]));
	}
#	elif LM_OS == LM_OS_BSD
	for (i = 0; i < aligned_size; i += sizeof(lm_uintptr_t)) {
		ptrace(PT_WRITE_D,
		       proc.pid,
		       (caddr_t)(&((lm_byte_t *)dst)[i]),
		       *(lm_uintptr_t *)(&buf[i]));
	}
#	endif
	
	LM_FREE(buf);
	ret = LM_TRUE;
	return ret;
}

static lm_bool_t
_LM_GetLibcMod(lm_module_t  mod,
	       lm_tstring_t path,
	       lm_void_t   *arg)
{
	lm_module_t *pmod = (lm_module_t *)arg;
	lm_tchar_t  *modname = (lm_tchar_t *)LM_NULL;

	{
		lm_tchar_t *tmp;

		for (tmp = path;
		     (tmp = LM_STRCHR(tmp, LM_STR('/')));
		     tmp = &tmp[1])
			modname = &tmp[1];
	}

	if (modname) {
		if (!LM_STRNCMP(modname, LM_STR("libc."), 5) ||
		    !LM_STRNCMP(modname, LM_STR("libc-"), 5)) {
			*pmod = mod;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}
#endif

/* libmem */

LM_API lm_bool_t
LM_DetourCode(lm_address_t src,
	      lm_address_t dst,
	      lm_detour_t  detour)
{
	lm_bool_t  ret = LM_FALSE;
	lm_byte_t *buf = (lm_byte_t *)LM_NULL;
	lm_size_t  size;
	lm_prot_t  old_prot = LM_PROT_XRW;

	size = _LM_DetourPayload(src, dst, detour, LM_GetProcessBits(), &buf);
	if (!size || !buf)
		return ret;
	
	if (!LM_ProtMemory(src, size, LM_PROT_XRW, &old_prot))
		goto _FREE_EXIT;

	ret = LM_WriteMemory(src, buf, size) == size ? LM_TRUE : ret;
	LM_ProtMemory(src, size, old_prot, (lm_prot_t *)LM_NULLPTR);
_FREE_EXIT:
	LM_FREE(buf);

	return ret;
}

LM_API lm_bool_t
LM_DetourCodeEx(lm_process_t proc,
		lm_address_t src,
		lm_address_t dst,
		lm_detour_t  detour)
{
	lm_bool_t  ret = LM_FALSE;
	lm_byte_t *buf = (lm_byte_t *)LM_NULL;
	lm_size_t  size;
	lm_prot_t  old_prot = LM_PROT_XRW;

	size = _LM_DetourPayload(src, dst, detour,
				 LM_GetProcessBitsEx(proc), &buf);
	if (!size || !buf)
		return ret;
	
	if (!LM_ProtMemoryEx(proc, src, size, LM_PROT_XRW, &old_prot))
		goto _FREE_EXIT;

	ret = LM_WriteMemoryEx(proc, src, buf, size) == size ? LM_TRUE : ret;
	LM_ProtMemoryEx(proc, src, size, old_prot, (lm_prot_t *)LM_NULLPTR);
_FREE_EXIT:
	LM_FREE(buf);

	return ret;
}

LM_API lm_address_t
LM_MakeTrampoline(lm_address_t src,
		  lm_size_t    size)
{
	lm_address_t tramp = (lm_address_t)LM_BAD;
	lm_prot_t    old_prot = LM_PROT_XRW;

	if (!LM_ProtMemory(src, size, LM_PROT_XRW, &old_prot))
		return tramp;

#	if LM_ARCH == LM_ARCH_X86
	{
		lm_byte_t *payload = (lm_byte_t *)LM_NULL;
		lm_size_t  payload_size;
		
		payload_size = _LM_DetourPayload(LM_NULLPTR,
						 &((lm_byte_t *)src)[size],
						 LM_DETOUR_JMP64,
						 LM_GetProcessBits(),
						 &payload);
		
		if (!payload_size || !payload)
			return tramp;

		tramp = LM_AllocMemory(size + payload_size, LM_PROT_XRW);
		if (!tramp)
			goto _FREE_PAYLOAD;
		
		LM_WriteMemory(tramp, (lm_bstring_t)src, size);
		LM_WriteMemory((lm_address_t)(&((lm_byte_t *)tramp)[size]),
			       payload,
			       payload_size);
	_FREE_PAYLOAD:
		LM_FREE(payload);
	}
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	LM_ProtMemory(src, size, old_prot, (lm_prot_t *)LM_NULLPTR);

	return tramp;
}

LM_API lm_address_t
LM_MakeTrampolineEx(lm_process_t proc,
		    lm_address_t src,
		    lm_size_t    size)
{
	lm_address_t tramp = (lm_address_t)LM_BAD;
	lm_prot_t    old_prot = LM_PROT_XRW;

	if (!LM_ProtMemoryEx(proc, src, size, LM_PROT_XRW, &old_prot))
		return tramp;

#	if LM_ARCH == LM_ARCH_X86
	{
		lm_byte_t *payload = (lm_byte_t *)LM_NULL;
		lm_size_t  payload_size;
		
		payload_size = _LM_DetourPayload(LM_NULLPTR,
						 &((lm_byte_t *)src)[size],
						 LM_DETOUR_JMP64,
						 LM_GetProcessBits(),
						 &payload);
		
		if (!payload_size || !payload)
			return tramp;

		tramp = LM_AllocMemoryEx(proc, size + payload_size,
					 LM_PROT_XRW);
		if (!tramp)
			goto _FREE_PAYLOAD;
		
		LM_WriteMemoryEx(proc, tramp, (lm_bstring_t)src, size);
		LM_WriteMemoryEx(proc,
				 (lm_address_t)(&((lm_byte_t *)tramp)[size]),
				 payload,
				 payload_size);
	_FREE_PAYLOAD:
		LM_FREE(payload);
	}
#	elif LM_ARCH == LM_ARCH_ARM
#	endif

	LM_ProtMemoryEx(proc, src, size, old_prot, (lm_prot_t *)LM_NULLPTR);

	return tramp;
}

LM_API lm_void_t
LM_DestroyTrampoline(lm_address_t tramp)
{
	if (tramp)
		LM_FreeMemory(tramp, 1);
}

LM_API lm_void_t
LM_DestroyTrampolineEx(lm_process_t proc,
		       lm_address_t tramp)
{
	if (tramp)
		LM_FreeMemoryEx(proc, tramp, 1);
}

LM_API lm_bool_t
LM_Assemble(lm_cstring_t code, lm_arch_t arch, lm_size_t bits, lm_inst_t *inst)
{
	lm_bool_t ret = LM_FALSE;
	ks_engine *ks;
	ks_arch ksarch;
	ks_mode ksmode;
	unsigned char *encode;
	size_t size;
	size_t count;

	if (!code || !inst)
		return ret;

	switch (arch) {
	case LM_ARCH_X86: ksarch = KS_ARCH_X86; break;
	case LM_ARCH_ARM: ksarch = KS_ARCH_ARM; break;
	default: return ret;
	}

	switch (bits) {
	case 32: ksmode = KS_MODE_32; break;
	case 64: ksmode = KS_MODE_64; break;
	default: return ret;
	}

	if (ks_open(ksarch, ksmode, &ks) != KS_ERR_OK)
		return ret;

	ks_asm(ks, code, 0, &encode, &size, &count);
	if (size <= 0 || size > LM_INST_SIZE)
		goto CLEAN_EXIT;

	inst->size = size;
	memcpy((void *)inst->bytes, (void *)encode, size);

	ks_free(encode);
	ret = LM_TRUE;
CLEAN_EXIT:
	ks_close(ks);
	return ret;
}

LM_API lm_bool_t
LM_Disassemble(lm_address_t code, lm_arch_t arch, lm_size_t bits, lm_inst_t *inst)
{
	lm_bool_t ret = LM_FALSE;
	csh cshandle;
	cs_insn *csinsn;
	cs_arch csarch;
	cs_mode csmode;
	size_t count;

	if (!code || !inst)
		return ret;

	switch (arch) {
	case LM_ARCH_X86: csarch = CS_ARCH_X86; break;
	case LM_ARCH_ARM: csarch = CS_ARCH_ARM; break;
	}

	switch (bits) {
	case 32: csmode = CS_MODE_32; break;
	case 64: csmode = CS_MODE_64; break;
	}

	if (cs_open(csarch, csmode, &cshandle) != CS_ERR_OK)
		return LM_FALSE;

	count = cs_disasm(cshandle, code, LM_INST_SIZE, 0, 1, &csinsn);
	if (count <= 0)
		goto CLEAN_EXIT;

	memcpy((void *)inst, (void *)&csinsn[0], sizeof(lm_inst_t));

	cs_free(csinsn, count);
	ret = LM_TRUE;
CLEAN_EXIT:
	cs_close(&cshandle);
	return ret;
}

LM_API lm_size_t
LM_CodeLength(lm_address_t code, lm_size_t minlength)
{
	lm_size_t length;
	lm_inst_t inst;
	for (length = 0; length < minlength; code = (lm_address_t)LM_OFFSET(code, length)) {
		if (LM_Disassemble(code, LM_ARCH, LM_BITS, &inst) == LM_FALSE)
			return 0;
		length += inst.size;
	}

	return length;
}

/****************************************/

LM_API lm_bool_t
LM_DebugAttach(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_ValidProcess(proc))
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (DebugActiveProcess(proc.pid))
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		if (ptrace(PTRACE_ATTACH, proc.pid, NULL, NULL) != -1)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		if (ptrace(PT_ATTACH, proc.pid, NULL, 0) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugDetach(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		if (DebugActiveProcessStop(proc.pid))
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		if (ptrace(PTRACE_DETACH, proc.pid, NULL, NULL) != -1)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		if (ptrace(PT_DETACH, proc.pid, NULL, 0) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_int_t
LM_DebugCheck(lm_process_t proc)
{
	lm_int_t state = (lm_int_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		BOOL Check;

		CheckRemoteDebuggerPresent(proc.handle, &Check);
		state = Check == TRUE ? LM_TRUE : LM_FALSE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		lm_tchar_t  status_path[64] = { 0 };
		lm_tchar_t *status_buf;
		lm_tchar_t *ptr;

		LM_SNPRINTF(status_path, LM_ARRLEN(status_path),
			    LM_STR("/proc/%d/status"), proc.pid);

		if (!_LM_OpenFileBuf(status_path, &status_buf))
			return state;
		
		ptr = LM_STRSTR(status_buf, LM_STR("TracerPid:"));
		ptr = LM_STRCHR(ptr, LM_STR('\t'));
		ptr = &ptr[1];

		if (LM_ATOI(ptr))
			state = LM_TRUE;
		else
			state = LM_FALSE;
		
		_LM_CloseFileBuf(&status_buf);
	}
#	elif LM_OS == LM_OS_BSD
	{

	}
#	endif

	return state;
}

LM_API lm_bool_t
LM_DebugRead(lm_process_t proc,
	     lm_address_t src,
	     lm_byte_t   *dst,
	     lm_size_t    size)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		ret = LM_ReadMemoryEx(proc, src, dst, size);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		ret = _LM_PtraceRead(proc, src, dst, size);
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugWrite(lm_process_t proc,
	      lm_address_t dst,
	      lm_byte_t   *src,
	      lm_size_t    size)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		ret = LM_WriteMemoryEx(proc, dst, src, size);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		ret = _LM_PtraceWrite(proc, dst, src, size);
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugGetRegs(lm_process_t proc,
		lm_regs_t   *regsbuf)
{
	lm_bool_t ret = LM_FALSE;

	if (!regsbuf)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		lm_tid_t tid;

		tid = LM_GetThreadIdEx(proc);
		if (tid != (lm_tid_t)LM_BAD) {
			HANDLE  hThread;

			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
			if (!hThread)
				return ret;
			
#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64) {
				if (GetThreadContext(hThread, &regsbuf->regs))
					ret = LM_TRUE;
			} else {
				if (Wow64GetThreadContext(hThread,
							  &regsbuf->regs32))
					ret = LM_TRUE;
			}
#			else
			if (GetThreadContext(hThread, &regsbuf->regs))
				ret = LM_TRUE;
#			endif

			CloseHandle(hThread);
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
#		if LM_ARCH == LM_ARCH_X86
		if (ptrace(PTRACE_GETREGS, proc.pid,
			   NULL, &regsbuf->regs) != -1 &&
		    ptrace(PTRACE_GETFPREGS, proc.pid,
			   NULL, &regsbuf->fpregs) != -1)
			ret = LM_TRUE;
		
		ret = LM_TRUE;
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
#	elif LM_OS == LM_OS_BSD
	{
#		if LM_ARCH == LM_ARCH_X86
		if (ptrace(PT_GETREGS, proc.pid,
			   (caddr_t)&regsbuf->regs, 0) != -1 &&
		    ptrace(PT_GETFPREGS, proc.pid,
			   (caddr_t)&regsbuf->fpregs, 0) != -1)
			ret = LM_TRUE;
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
#	endif

	return ret;
}

LM_API lm_void_t *
LM_DebugPickReg(lm_datloc_t regid,
	       lm_regs_t  *regs)
{
	lm_void_t *preg = (lm_void_t *)LM_NULL;

#	if LM_OS == LM_OS_WIN
#	if LM_ARCH == LM_ARCH_X86
#	if LM_BITS == 64
	switch (regid) {
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs32.Eax;
		break;
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs32.Ebx;
		break;
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs32.Ecx;
		break;
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs32.Edx;
		break;
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs32.Esi;
		break;
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs32.Edi;
		break;
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs32.Esp;
		break;
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs32.Ebp;
		break;
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs32.Eip;
		break;
	case LM_DATLOC_RAX:
		preg = (lm_void_t *)&regs->regs.Rax;
		break;
	case LM_DATLOC_RBX:
		preg = (lm_void_t *)&regs->regs.Rbx;
		break;
	case LM_DATLOC_RCX:
		preg = (lm_void_t *)&regs->regs.Rcx;
		break;
	case LM_DATLOC_RDX:
		preg = (lm_void_t *)&regs->regs.Rdx;
		break;
	case LM_DATLOC_RSI:
		preg = (lm_void_t *)&regs->regs.Rsi;
		break;
	case LM_DATLOC_RDI:
		preg = (lm_void_t *)&regs->regs.Rdi;
		break;
	case LM_DATLOC_RSP:
		preg = (lm_void_t *)&regs->regs.Rsp;
		break;
	case LM_DATLOC_RBP:
		preg = (lm_void_t *)&regs->regs.Rbp;
		break;
	case LM_DATLOC_RIP:
		preg = (lm_void_t *)&regs->regs.Rip;
		break;
	case LM_DATLOC_R8:
		preg = (lm_void_t *)&regs->regs.R8;
		break;
	case LM_DATLOC_R9:
		preg = (lm_void_t *)&regs->regs.R9;
		break;
	case LM_DATLOC_R10:
		preg = (lm_void_t *)&regs->regs.R10;
		break;
	case LM_DATLOC_R11:
		preg = (lm_void_t *)&regs->regs.R11;
		break;
	case LM_DATLOC_R12:
		preg = (lm_void_t *)&regs->regs.R12;
		break;
	case LM_DATLOC_R13:
		preg = (lm_void_t *)&regs->regs.R13;
		break;
	case LM_DATLOC_R14:
		preg = (lm_void_t *)&regs->regs.R14;
		break;
	case LM_DATLOC_R15:
		preg = (lm_void_t *)&regs->regs.R15;
		break;
	}
#	else
	switch (regid) {
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.Eax;
		break;
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.Ebx;
		break;
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.Ecx;
		break;
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.Edx;
		break;
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.Esi;
		break;
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.Edi;
		break;
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.Esp;
		break;
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.Ebp;
		break;
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.Eip;
		break;
	}
#	endif
#	elif LM_ARCH == LM_ARCH_ARM
#	endif
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
#	if LM_ARCH == LM_ARCH_X86
#	if LM_BITS == 64
	switch (regid) {
	case LM_DATLOC_RAX:
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.rax;
		break;
	case LM_DATLOC_RBX:
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.rbx;
		break;
	case LM_DATLOC_RCX:
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.rcx;
		break;
	case LM_DATLOC_RDX:
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.rdx;
		break;
	case LM_DATLOC_RSI:
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.rsi;
		break;
	case LM_DATLOC_RDI:
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.rdi;
		break;
	case LM_DATLOC_RSP:
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.rsp;
		break;
	case LM_DATLOC_RBP:
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.rbp;
		break;
	case LM_DATLOC_RIP:
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.rip;
		break;
	case LM_DATLOC_R8:
		preg = (lm_void_t *)&regs->regs.r8;
		break;
	case LM_DATLOC_R9:
		preg = (lm_void_t *)&regs->regs.r9;
		break;
	case LM_DATLOC_R10:
		preg = (lm_void_t *)&regs->regs.r10;
		break;
	case LM_DATLOC_R11:
		preg = (lm_void_t *)&regs->regs.r11;
		break;
	case LM_DATLOC_R12:
		preg = (lm_void_t *)&regs->regs.r12;
		break;
	case LM_DATLOC_R13:
		preg = (lm_void_t *)&regs->regs.r13;
		break;
	case LM_DATLOC_R14:
		preg = (lm_void_t *)&regs->regs.r14;
		break;
	case LM_DATLOC_R15:
		preg = (lm_void_t *)&regs->regs.r15;
		break;
	}
#	else
	switch (regid) {
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.eax;
		break;
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.ebx;
		break;
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.ecx;
		break;
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.edx;
		break;
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.esi;
		break;
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.edi;
		break;
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.esp;
		break;
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.ebp;
		break;
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.eip;
		break;
	}
#	endif
#	elif LM_ARCH == LM_ARCH_ARM
#	endif
#	elif LM_OS == LM_OS_BSD
#	if LM_ARCH == LM_ARCH_X86
#	if LM_BITS == 64
	switch (regid) {
	case LM_DATLOC_RAX:
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.r_rax;
		break;
	case LM_DATLOC_RBX:
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.r_rbx;
		break;
	case LM_DATLOC_RCX:
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.r_rcx;
		break;
	case LM_DATLOC_RDX:
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.r_rdx;
		break;
	case LM_DATLOC_RSI:
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.r_rsi;
		break;
	case LM_DATLOC_RDI:
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.r_rdi;
		break;
	case LM_DATLOC_RSP:
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.r_rsp;
		break;
	case LM_DATLOC_RBP:
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.r_rbp;
		break;
	case LM_DATLOC_RIP:
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.r_rip;
		break;
	case LM_DATLOC_R8:
		preg = (lm_void_t *)&regs->regs.r_r8;
		break;
	case LM_DATLOC_R9:
		preg = (lm_void_t *)&regs->regs.r_r9;
		break;
	case LM_DATLOC_R10:
		preg = (lm_void_t *)&regs->regs.r_r10;
		break;
	case LM_DATLOC_R11:
		preg = (lm_void_t *)&regs->regs.r_r11;
		break;
	case LM_DATLOC_R12:
		preg = (lm_void_t *)&regs->regs.r_r12;
		break;
	case LM_DATLOC_R13:
		preg = (lm_void_t *)&regs->regs.r_r13;
		break;
	case LM_DATLOC_R14:
		preg = (lm_void_t *)&regs->regs.r_r14;
		break;
	case LM_DATLOC_R15:
		preg = (lm_void_t *)&regs->regs.r_r15;
		break;
	}
#	else
	switch (regid) {
	case LM_DATLOC_EAX:
		preg = (lm_void_t *)&regs->regs.r_eax;
		break;
	case LM_DATLOC_EBX:
		preg = (lm_void_t *)&regs->regs.r_ebx;
		break;
	case LM_DATLOC_ECX:
		preg = (lm_void_t *)&regs->regs.r_ecx;
		break;
	case LM_DATLOC_EDX:
		preg = (lm_void_t *)&regs->regs.r_edx;
		break;
	case LM_DATLOC_ESI:
		preg = (lm_void_t *)&regs->regs.r_esi;
		break;
	case LM_DATLOC_EDI:
		preg = (lm_void_t *)&regs->regs.r_edi;
		break;
	case LM_DATLOC_ESP:
		preg = (lm_void_t *)&regs->regs.r_esp;
		break;
	case LM_DATLOC_EBP:
		preg = (lm_void_t *)&regs->regs.r_ebp;
		break;
	case LM_DATLOC_EIP:
		preg = (lm_void_t *)&regs->regs.r_eip;
		break;
	}
#	endif
#	elif LM_ARCH == LM_ARCH_ARM
#	endif
#	endif

	return preg;
}

LM_API lm_bool_t
LM_DebugSetRegs(lm_process_t proc,
		lm_regs_t    regs)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		lm_tid_t tid;

		tid = LM_GetThreadIdEx(proc);
		if (tid != (lm_tid_t)LM_BAD) {
			HANDLE  hThread;

			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
			if (!hThread)
				return ret;
			
#			if LM_BITS == 64
			if (LM_GetProcessBitsEx(proc) == 64) {
				if (SetThreadContext(hThread, &regs.regs))
					ret = LM_TRUE;
			} else {
				if (Wow64SetThreadContext(hThread,
							  &regs.regs32))
					ret = LM_TRUE;
			}
#			else
			if (SetThreadContext(hThread, &regs.regs))
				ret = LM_TRUE;
#			endif

			CloseHandle(hThread);
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
#		if LM_ARCH == LM_ARCH_X86
		if (ptrace(PTRACE_SETREGS, proc.pid,
			   NULL, &regs.regs) != -1 &&
		    ptrace(PTRACE_SETFPREGS, proc.pid,
		    	   NULL, &regs.fpregs) != -1)
			ret = LM_TRUE;
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
#	elif LM_OS == LM_OS_BSD
	{
#		if LM_ARCH == LM_ARCH_X86
		if (ptrace(PT_SETREGS, proc.pid,
			   (caddr_t)&regs.regs, 0) != -1 &&
		    ptrace(PT_SETFPREGS, proc.pid,
		    	   (caddr_t)&regs.fpregs, 0) != -1)
			ret = LM_TRUE;
#		elif LM_ARCH == LM_ARCH_ARM
#		endif
	}
#	endif

	return ret;
}

LM_API lm_uintptr_t
LM_DebugReadReg(lm_datloc_t regid,
		lm_regs_t   regs)
{
	lm_uintptr_t val = (lm_uintptr_t)LM_BAD;
	lm_void_t   *preg;

	preg = LM_DebugPickReg(regid, &regs);
	if (preg) {
#		if LM_OS == LM_OS_WIN
#		if LM_BITS == 64
		if (regid < LM_DATLOC_RAX) {
			/* 32-bit register */

			val = (lm_uintptr_t)(*(lm_uint32_t *)preg);
		} else {
			val = *(lm_uintptr_t *)preg;
		}
#		else
		val = *(lm_uintptr_t *)preg;
#		endif
#		else
		val = *(lm_uintptr_t *)preg;
#		endif
	}

	return val;
}

LM_API lm_bool_t
LM_DebugWriteReg(lm_datloc_t  regid,
		 lm_uintptr_t data,
		 lm_regs_t   *regs)
{
	lm_bool_t    ret = LM_FALSE;
	lm_void_t   *preg;

	preg = LM_DebugPickReg(regid, regs);
	if (preg) {
#		if LM_OS == LM_OS_WIN
#		if LM_BITS == 64
		if (regid < LM_DATLOC_RAX)
			*(lm_uint32_t *)preg = (lm_uint32_t)data;
		else
			*(lm_uintptr_t *)preg = data;
#		else
		*(lm_uintptr_t *)preg = data;
#		endif
#		else
		*(lm_uintptr_t *)preg = data;
#		endif

		ret = LM_TRUE;
	}

	return ret;
}

LM_API lm_bool_t
LM_DebugContinue(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{

	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		if (ptrace(PTRACE_CONT, proc.pid, NULL, NULL) != -1)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		if (ptrace(PT_CONTINUE, proc.pid, (caddr_t)1, 0) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugStep(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	{
		if (ptrace(PTRACE_SINGLESTEP, proc.pid, NULL, NULL) != -1)
			ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_BSD
	{
		if (ptrace(PT_STEP, proc.pid, (caddr_t)NULL, 0) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugWait(lm_void_t)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{
		
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		int status;

		if (wait(&status) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugWaitProcess(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

#	if LM_OS == LM_OS_WIN
	{

	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		int status;

		if (waitpid(proc.pid, &status, WSTOPPED) != -1)
			ret = LM_TRUE;
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_DebugInject(lm_process_t proc,
	       lm_bstring_t payload,
	       lm_size_t    size,
	       lm_regs_t    regs,
	       lm_regs_t   *post_regs)
{
	return _LM_DebugInject(proc,
			       payload,
			       size,
			       regs,
			       post_regs,
			       LM_DebugContinue);
}

LM_API lm_bool_t
LM_DebugInjectSingle(lm_process_t proc,
		     lm_bstring_t payload,
		     lm_size_t    size,
		     lm_regs_t    regs,
		     lm_regs_t   *post_regs)
{
	return _LM_DebugInject(proc,
			       payload,
			       size,
			       regs,
			       post_regs,
			       LM_DebugStep);
}

#endif
