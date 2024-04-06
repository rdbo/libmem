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

#include <libmem/libmem.h>
 #include "arch/arch.h"
 #include <alloca.h>

LM_API lm_size_t LM_CALL
LM_HookCode(lm_address_t  from,
	    lm_address_t  to,
	    lm_address_t *trampoline_out)
{
	lm_size_t trampsize = 0;
	lm_byte_t *payload;
	lm_size_t hooksize = 0;
	lm_address_t tramp;
	lm_size_t aligned_size;
	lm_prot_t old_prot;
	
	if (from == LM_ADDRESS_BAD || to == LM_ADDRESS_BAD)
		return trampsize;
	
	hooksize = generate_hook_payload(from, to, LM_GetBits(), &payload);
	if (hooksize == 0)
		return trampsize;

	aligned_size = LM_CodeLength(from, hooksize);
	if (aligned_size == 0)
		goto FREE_EXIT;

	if (!LM_ProtMemory(from, hooksize, LM_PROT_XRW, &old_prot))
		goto FREE_EXIT;

	if (trampoline_out) {
		/*
		 * NOTE: The trampoline jump back code is the same as the hook code, but
		 *       with a different jump address.
		 */
		tramp = LM_AllocMemory(aligned_size + hooksize, LM_PROT_XRW);
		if (tramp == LM_ADDRESS_BAD)
			goto PROT_EXIT;

		if (LM_WriteMemory(tramp, from, aligned_size) == 0)
			goto TRAMP_EXIT;

		/*
		 * Write valid instructions at the end of the gateway to prevent 'LM_CodeLength' malfunction.
		 * This is a hack that allows us to call 'LM_HookCode' on the trampoline instead of re-doing
		 * the same functionality over here.
		 */
		if (LM_WriteMemory(tramp + aligned_size, payload, hooksize) == 0)
			goto TRAMP_EXIT;

		if (LM_HookCode(tramp + aligned_size, from + aligned_size, LM_NULLPTR) == 0)
			goto TRAMP_EXIT;

		*trampoline_out = tramp;
	}

	if (LM_WriteMemory(from, payload, hooksize) == 0)
		goto TRAMP_EXIT;

	trampsize = aligned_size;
	goto PROT_EXIT;
TRAMP_EXIT:
	LM_FreeMemory(tramp, aligned_size + hooksize);
PROT_EXIT:
	LM_ProtMemory(from, hooksize, old_prot, LM_NULLPTR);
FREE_EXIT:
	LM_FreePayload(payload);

	return trampsize; /* NOTE: Even if the trampoline was not generated, 
			   *       the function will still return what would've
			   *       been its size (without the jump back) */
}

/********************************/

LM_API lm_size_t LM_CALL
LM_HookCodeEx(const lm_process_t *process,
	      lm_address_t        from,
	      lm_address_t        to,
	      lm_address_t       *trampoline_out)
{
	lm_size_t trampsize = 0;
	lm_byte_t *payload;
	lm_size_t hooksize = 0;
	lm_address_t tramp;
	lm_size_t aligned_size;
	lm_prot_t old_prot;
	
	if (!process || from == LM_ADDRESS_BAD || to == LM_ADDRESS_BAD)
		return trampsize;
	
	hooksize = generate_hook_payload(from, to, process->bits, &payload);
	if (hooksize == 0)
		return trampsize;

	aligned_size = LM_CodeLengthEx(process, from, hooksize);
	if (aligned_size == 0)
		goto FREE_EXIT;

	if (!LM_ProtMemoryEx(process, from, hooksize, LM_PROT_XRW, &old_prot))
		goto FREE_EXIT;

	if (trampoline_out) {
		lm_byte_t *from_buf;

		from_buf = (lm_byte_t *)alloca(aligned_size);
		if (!LM_ReadMemoryEx(process, from, from_buf, aligned_size))
			goto PROT_EXIT;

		/*
		 * NOTE: The trampoline jump back code is the same as the hook code, but
		 *       with a different jump address.
		 */
		tramp = LM_AllocMemoryEx(process, aligned_size + hooksize, LM_PROT_XRW);
		if (tramp == LM_ADDRESS_BAD)
			goto PROT_EXIT;

		if (LM_WriteMemoryEx(process, tramp, from_buf, aligned_size) == 0)
			goto TRAMP_EXIT;

		/*
		 * Write valid instructions at the end of the gateway to prevent 'LM_CodeLengthEx' malfunction.
		 * This is a hack that allows us to call 'LM_HookCodeEx' on the trampoline instead of re-doing
		 * the same functionality over here.
		 */
		if (LM_WriteMemoryEx(process, tramp + aligned_size, payload, hooksize) == 0)
			goto TRAMP_EXIT;

		if (LM_HookCodeEx(process, tramp + aligned_size, from + aligned_size, LM_NULLPTR) == 0)
			goto TRAMP_EXIT;

		*trampoline_out = tramp;
	}

	if (LM_WriteMemoryEx(process, from, payload, hooksize) == 0)
		goto TRAMP_EXIT;

	trampsize = aligned_size;
	goto PROT_EXIT;
TRAMP_EXIT:
	LM_FreeMemoryEx(process, tramp, aligned_size + hooksize);
PROT_EXIT:
	LM_ProtMemoryEx(process, from, hooksize, old_prot, LM_NULLPTR);
FREE_EXIT:
	LM_FreePayload(payload);

	return trampsize; /* NOTE: Even if the trampoline was not generated, 
			   *       the function will still return what would've
			   *       been its size (without the jump back) */
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_UnhookCode(lm_address_t from,
	      lm_address_t trampoline,
	      lm_size_t    size)
{
	lm_prot_t old_prot;
	
	if (from == LM_ADDRESS_BAD || trampoline == LM_ADDRESS_BAD || size == 0)
		return LM_FALSE;

	if (!LM_ProtMemory(from, size, LM_PROT_XRW, &old_prot))
		return LM_FALSE;

	LM_WriteMemory(from, trampoline, size);
	LM_ProtMemory(from, size, old_prot, LM_NULLPTR);

	/* WARN: This should be fine because 'LM_FreeMemory' works with page sizes,
	 *       but it neglects the size of the jump back after the trampoline's 
	 *       original code! */
	/* TODO: Fix the issue in the warn above */
	LM_FreeMemory(trampoline, size);

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_UnhookCodeEx(const lm_process_t *process,
		lm_address_t        from,
		lm_address_t        trampoline,
		lm_size_t           size)
{
	lm_prot_t old_prot;
	
	if (!process || from == LM_ADDRESS_BAD || trampoline == LM_ADDRESS_BAD || size == 0)
		return LM_FALSE;

	if (!LM_ProtMemoryEx(process, from, size, LM_PROT_XRW, &old_prot))
		return LM_FALSE;

	LM_WriteMemoryEx(process, from, trampoline, size);
	LM_ProtMemoryEx(process, from, size, old_prot, LM_NULLPTR);

	/* WARN: This should be fine because 'LM_FreeMemory' works with page sizes,
	 *       but it neglects the size of the jump back after the trampoline's 
	 *       original code! */
	/* TODO: Fix the issue in the warn above */
	LM_FreeMemoryEx(process, trampoline, size);

	return LM_TRUE;
}
