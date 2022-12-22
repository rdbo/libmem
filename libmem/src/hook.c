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

