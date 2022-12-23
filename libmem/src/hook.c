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
			     /* these NOPs will become the jump address */
			     "nop; nop; nop; nop; nop; nop; nop; nop");
	} else {
		LM_CSNPRINTF(code, sizeof(code), "jmp %p", (void *)to);
	}

	size = LM_AssembleEx(code, LM_ARCH, bits, from, pcodebuf);

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

	LM_ASSERT(from != LM_NULLPTR && to != LM_NULLPTR);

	if (!(codesize = _LM_GenerateHook(from, to, LM_BITS, &codebuf)))
		return ret;

	/* Get minimum hook size that doesn't overwrite the existing instructions */
	alignedsize = LM_CodeLength(from, codesize);
	if (!alignedsize)
		goto FREE_EXIT;

	if (!LM_ProtMemory(from, codesize, LM_PROT_XRW, &old_prot))
		goto FREE_EXIT;

	/* TODO: Add jump back for trampoline */
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
	LM_FreeCodeBuffer(codebuf);

	return ret;
}

LM_API lm_bool_t
LM_UnhookCode(lm_address_t  from,
	      lm_address_t  trampoline,
	      lm_size_t     size)
{
	lm_prot_t old_prot;

	if (!LM_ProtMemory(from, size, LM_PROT_XRW, &old_prot))
		return LM_FALSE;

	LM_WriteMemory(from, trampoline, size);

	LM_ProtMemory(from, size, old_prot, LM_NULLPTR);
	LM_FreeMemory(trampoline, size);

	return LM_TRUE;
}

LM_API lm_bool_t
LM_HookCodeEx(lm_address_t  from,
	      lm_address_t  to,
	      lm_address_t *ptrampoline)
{
	/* TODO: Implement */
}

LM_API lm_bool_t
LM_UnhookCodeEx(lm_address_t  from,
		lm_address_t *ptrampoline)
{
	/* TODO: Implement */
}

