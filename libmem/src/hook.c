#include "internal.h"

#if LM_ARCH == LM_ARCH_X86
LM_PRIVATE lm_size_t
_LM_GenerateHook(lm_address_t from,
		 lm_address_t to,
		 lm_size_t    bits,
		 lm_byte_t  **pcodebuf)
{
	lm_char_t code[255];
	lm_size_t size;

	if (bits == 64) {
		/* dereference of RIP will be the jump address */
		LM_CSNPRINTF(code, sizeof(code),
			     "jmp [rip];"
			     /* these nops will become the jump address */
			     "nop; nop; nop; nop; nop; nop; nop; nop");
	} else {
		LM_CSNPRINTF(code, sizeof(code), "jmp %p", (void *)to);
	}

	size = LM_AssembleEx(code, LM_ARCH, bits, from, pcodebuf);

	/* replace nops with jump address */
	if (size > 0 && bits == 64) {
		*(lm_uint64_t *)(
			LM_OFFSET(*pcodebuf, size - sizeof(lm_uint64_t))
		) = (lm_uint64_t)to;
	}

	return size;
}
#elif LM_ARCH == LM_ARCH_ARM
LM_PRIVATE lm_size_t
_LM_GenerateHook(lm_address_t from,
		 lm_address_t to,
		 lm_byte_t  **pcodebuf)
{
	/* TODO: Implement */
	return 0;
}
#endif

LM_API lm_size_t
LM_HookCode(lm_address_t  from,
	    lm_address_t  to,
	    lm_address_t *ptrampoline)
{
	lm_size_t  ret = 0;
	lm_byte_t *codebuf;
	lm_prot_t  old_prot;
	lm_size_t  codesize;
	lm_size_t  alignedsize;

	LM_ASSERT(from != LM_ADDRESS_BAD && to != LM_ADDRESS_BAD);

	if (!(codesize = _LM_GenerateHook(from, to, LM_BITS, &codebuf)))
		return ret;

	/* Get minimum hook size that doesn't overwrite the existing instructions */
	alignedsize = LM_CodeLength(from, codesize);
	if (!alignedsize)
		goto FREE_EXIT;

	if (!LM_ProtMemory(from, codesize, LM_PROT_XRW, &old_prot))
		goto FREE_EXIT;

	if (ptrampoline) {
		/* the jump back code is the same as the hook code, but
		   with a different jump address */
		*ptrampoline = LM_AllocMemory(alignedsize + codesize, LM_PROT_XRW);
		if (*ptrampoline == LM_ADDRESS_BAD)
			goto FREE_EXIT;

		LM_ReadMemory(from, *ptrampoline, alignedsize);

		/* place jump back code on trampoline after the
		   original instructions */
		LM_HookCode((lm_address_t)LM_OFFSET(*ptrampoline, alignedsize),
			    (lm_address_t)LM_OFFSET(from, alignedsize),
			    LM_NULLPTR);
	}

	LM_WriteMemory(from, codebuf, codesize);

	LM_ProtMemory(from, codesize, old_prot, LM_NULLPTR);

	ret = alignedsize;
FREE_EXIT:
	LM_FreeCodeBuffer(&codebuf);

	return ret;
}

/********************************/

LM_API lm_bool_t
LM_UnhookCode(lm_address_t  from,
	      lm_address_t *ptrampoline,
	      lm_size_t     size)
{
	lm_prot_t old_prot;
	lm_address_t trampoline;

	LM_ASSERT(from != LM_ADDRESS_BAD &&
		  ptrampoline != LM_NULLPTR &&
		  *ptrampoline != LM_ADDRESS_BAD &&
		  size > 0);

	trampoline = *ptrampoline;

	if (!LM_ProtMemory(from, size, LM_PROT_XRW, &old_prot))
		return LM_FALSE;

	LM_WriteMemory(from, trampoline, size);

	LM_ProtMemory(from, size, old_prot, LM_NULLPTR);
	LM_FreeMemory(trampoline, size);

	*ptrampoline = LM_ADDRESS_BAD;

	return LM_TRUE;
}

/********************************/

LM_API lm_size_t
LM_HookCodeEx(lm_process_t *pproc,
	      lm_address_t  from,
	      lm_address_t  to,
	      lm_address_t *ptrampoline)
{
	lm_size_t  ret = 0;
	lm_size_t  bits;
	lm_byte_t *codebuf;
	lm_prot_t  old_prot;
	lm_size_t  codesize;
	lm_size_t  alignedsize;

	LM_ASSERT(pproc != LM_NULLPTR &&
		  from != LM_ADDRESS_BAD &&
		  to != LM_ADDRESS_BAD);

	bits = LM_GetProcessBitsEx(pproc);

	if (!(codesize = _LM_GenerateHook(from, to, bits, &codebuf)))
		return ret;

	/* Get minimum hook size that doesn't overwrite the existing instructions */
	alignedsize = LM_CodeLengthEx(pproc, from, codesize);
	if (!alignedsize)
		goto FREE_EXIT;

	if (!LM_ProtMemoryEx(pproc, from, codesize, LM_PROT_XRW, &old_prot))
		goto FREE_EXIT;

	if (ptrampoline) {
		/* the jump back code is the same as the hook code, but
		   with a different jump address */
		lm_byte_t *tramp_code;

		tramp_code = (lm_byte_t *)LM_MALLOC(alignedsize + codesize);
		if (!tramp_code)
			goto FREE_EXIT;

		/* read the original bytes that will be written to the trampoline */
		LM_ReadMemoryEx(pproc, from, tramp_code, alignedsize);

		*ptrampoline = LM_AllocMemoryEx(pproc,
						alignedsize + codesize,
						LM_PROT_XRW);
		if (*ptrampoline != LM_ADDRESS_BAD) {
			LM_WriteMemoryEx(pproc, *ptrampoline,
					 tramp_code, alignedsize);

			/* place jump back code on trampoline after the
			   original instructions */
			LM_HookCodeEx(
				pproc,
				(lm_address_t)LM_OFFSET(*ptrampoline, alignedsize),
				(lm_address_t)LM_OFFSET(from, alignedsize),
				LM_NULLPTR
			);
		}

		LM_FREE(tramp_code);

		if (*ptrampoline == LM_ADDRESS_BAD)
			goto FREE_EXIT;
	}

	LM_WriteMemoryEx(pproc, from, codebuf, codesize);

	LM_ProtMemoryEx(pproc, from, codesize, old_prot, LM_NULLPTR);

	ret = alignedsize;
FREE_EXIT:
	LM_FreeCodeBuffer(codebuf);

	return ret;
}

/********************************/

LM_API lm_bool_t
LM_UnhookCodeEx(lm_process_t *pproc,
		lm_address_t  from,
		lm_address_t *ptrampoline,
		lm_size_t     size)
{
	lm_prot_t old_prot;
	lm_address_t trampoline;

	LM_ASSERT(pproc != LM_NULLPTR &&
		  from != LM_ADDRESS_BAD &&
		  ptrampoline != LM_NULLPTR &&
		  *ptrampoline != LM_ADDRESS_BAD &&
		  size > 0);

	trampoline = *ptrampoline;

	if (!LM_ProtMemoryEx(pproc, from, size, LM_PROT_XRW, &old_prot))
		return LM_FALSE;

	LM_WriteMemoryEx(pproc, from, trampoline, size);

	LM_ProtMemory(from, size, old_prot, LM_NULLPTR);
	LM_FreeMemory(trampoline, size);

	*ptrampoline = LM_ADDRESS_BAD;

	return LM_TRUE;
}

