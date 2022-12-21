LM_API lm_address_t
LM_DataScan(lm_bstring_t data,
	    lm_size_t    size,
	    lm_address_t addr,
	    lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t   *ptr;
	lm_page_t    oldpage;

	LM_ASSERT(data != LM_NULLPTR && size > 0 &&
		  addr != LM_ADDRESS_BAD && scansize > 0);

	if (!LM_GetPage(addr, &oldpage))
		return match;
	
	LM_ProtMemory(oldpage.base, oldpage.size,
		      LM_PROT_XRW, (lm_prot_t *)LM_NULL);

	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		if ((lm_uintptr_t)ptr >= (lm_uintptr_t)oldpage.end) {
			LM_ProtMemory(oldpage.base, oldpage.size,
				      oldpage.prot, (lm_prot_t *)LM_NULL);

			if (!LM_GetPage(ptr, &oldpage))
				break;
			
			LM_ProtMemory(oldpage.base, oldpage.size,
				      LM_PROT_XRW, (lm_prot_t *)LM_NULL);
		}

		for (i = 0; check && i < size; ++i) {
			if (ptr[i] != data[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	LM_ProtMemory(oldpage.base, oldpage.size,
		      oldpage.prot, (lm_prot_t *)LM_NULL);

	return match;
}

/********************************/

LM_API lm_address_t
LM_DataScanEx(lm_process_t proc,
	      lm_bstring_t data,
	      lm_size_t    size,
	      lm_address_t addr,
	      lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t   *ptr;
	lm_page_t    oldpage;

	LM_ASSERT(_LM_ValidProcess(proc) && data != LM_NULLPTR &&
		  size > 0 && addr != LM_NULLPTR && scansize > 0);

	if (!LM_GetPageEx(proc, addr, &oldpage))
		return match;
	
	LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
			LM_PROT_XRW, (lm_prot_t *)LM_NULL);

	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		if ((lm_uintptr_t)ptr >= (lm_uintptr_t)oldpage.end) {
			LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
					oldpage.prot, (lm_prot_t *)LM_NULL);

			if (!LM_GetPageEx(proc, ptr, &oldpage))
				break;
			
			LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
					LM_PROT_XRW, (lm_prot_t *)LM_NULL);
		}

		for (i = 0; check && i < size; ++i) {
			lm_byte_t b;

			LM_ReadMemoryEx(proc, (lm_address_t)&ptr[i], &b, sizeof(b));

			if (b != data[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
			oldpage.prot, (lm_prot_t *)LM_NULL);

	return match;
}

/********************************/

LM_API lm_address_t
LM_PatternScan(lm_bstring_t pattern,
	       lm_tstring_t mask,
	       lm_address_t addr,
	       lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_size_t    size;
	lm_page_t    oldpage;
	lm_byte_t   *ptr;

	LM_ASSERT(pattern != LM_NULLPTR && mask != LM_NULLPTR &&
		  addr != LM_ADDRESS_BAD && scansize > 0);

	size = LM_STRLEN(mask);
	if (!size)
		return match;
	
	if (!LM_GetPage(addr, &oldpage))
		return match;
	
	LM_ProtMemory(oldpage.base, oldpage.size,
		      LM_PROT_XRW, (lm_prot_t *)LM_NULL);
	
	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		if ((lm_uintptr_t)ptr >= (lm_uintptr_t)oldpage.end) {
			LM_ProtMemory(oldpage.base, oldpage.size,
				      oldpage.prot, (lm_prot_t *)LM_NULL);

			if (!LM_GetPage(ptr, &oldpage))
				break;
			
			LM_ProtMemory(oldpage.base, oldpage.size,
				      LM_PROT_XRW, (lm_prot_t *)LM_NULL);
		}

		for (i = 0; check && i < size; ++i) {
			if (LM_CHKMASK(mask[i]) && ptr[i] != pattern[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}
	
	LM_ProtMemory(oldpage.base, oldpage.size,
		      oldpage.prot, (lm_prot_t *)LM_NULL);

	return match;
}

/********************************/

LM_API lm_address_t
LM_PatternScanEx(lm_process_t proc,
		 lm_bstring_t pattern,
		 lm_tstring_t mask,
		 lm_address_t addr,
		 lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_size_t    size;
	lm_page_t    oldpage;
	lm_byte_t   *ptr;

	LM_ASSERT(_LM_ValidProcess(proc) && pattern != LM_NULLPTR &&
		  mask != LM_NULLPTR && addr != LM_ADDRESS_BAD &&
		  scansize > 0);

	size = LM_STRLEN(mask);
	if (!size)
		return match;
	
	if (!LM_GetPageEx(proc, addr, &oldpage))
		return match;
	
	LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
			LM_PROT_XRW, (lm_prot_t *)LM_NULL);
	
	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		if ((lm_uintptr_t)ptr >= (lm_uintptr_t)oldpage.end) {
			LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
					oldpage.prot, (lm_prot_t *)LM_NULL);

			if (!LM_GetPageEx(proc, ptr, &oldpage))
				break;
			
			LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
					LM_PROT_XRW, (lm_prot_t *)LM_NULL);
		}

		for (i = 0; check && i < size; ++i) {
			lm_byte_t b;

			LM_ReadMemoryEx(proc, &ptr[i], &b, sizeof(b));

			if (LM_CHKMASK(mask[i]) && b != pattern[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}
	
	LM_ProtMemoryEx(proc, oldpage.base, oldpage.size,
			oldpage.prot, (lm_prot_t *)LM_NULL);

	return match;
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_ParseSig(lm_tstring_t  sig,
	     lm_bstring_t *ppattern,
	     lm_tstring_t *pmask)
{
	lm_bool_t    ret = LM_FALSE;
	lm_byte_t   *pattern = (lm_byte_t *)LM_NULL;
	lm_tchar_t  *mask = (lm_tchar_t *)LM_NULL;
	lm_size_t    len = 0;
	lm_tchar_t  *ptr;
	
	for (ptr = sig; ptr; ptr = LM_STRCHR(ptr, LM_STR(' '))) {
		lm_byte_t  *old_pattern = pattern;
		lm_tchar_t *old_mask = mask;
		lm_byte_t   curbyte = 0;
		lm_tchar_t  curchar = LM_MASK_UNKNOWN;

		pattern = (lm_byte_t *)LM_CALLOC(len + 1, sizeof(lm_byte_t));
		if (old_pattern) {
			if (pattern)
				LM_MEMCPY(pattern, old_pattern, len * sizeof(lm_byte_t));
			LM_FREE(old_pattern);
		}

		if (!pattern) {
			if (mask)
				LM_FREE(mask);
			return ret;
		}

		mask = (lm_tchar_t *)LM_CALLOC(len + 2, sizeof(lm_tchar_t));
		if (old_mask) {
			if (mask)
				LM_STRNCPY(mask, old_mask, len);
			
			LM_FREE(old_mask);
		}

		if (!mask) {
			LM_FREE(pattern);
			return ret;
		}

		if (ptr != sig)
			ptr = &ptr[1];
		
		if (!LM_RCHKMASK(*ptr)) {
			curbyte = (lm_byte_t)LM_STRTOP(ptr, NULL, 16);
			curchar = LM_MASK_KNOWN;
		}

		pattern[len] = curbyte;
		mask[len++] = curchar;
		mask[len] = LM_STR('\x00');
	}

	*ppattern = pattern;
	*pmask = mask;
	ret = LM_TRUE;
	
	return ret;
}

LM_API lm_address_t
LM_SigScan(lm_tstring_t sig,
	   lm_address_t addr,
	   lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_bstring_t pattern = (lm_byte_t *)LM_NULL;
	lm_tstring_t mask = (lm_tchar_t *)LM_NULL;

	LM_ASSERT(sig != LM_NULLPTR && addr != LM_ADDRESS_BAD);

	if (!_LM_ParseSig(sig, &pattern, &mask))
		return match;
	
	match = LM_PatternScan(pattern, mask, addr, scansize);

	LM_FREE(pattern);
	LM_FREE(mask);

	return match;
}

/********************************/

LM_API lm_address_t
LM_SigScanEx(lm_process_t proc,
	     lm_tstring_t sig,
	     lm_address_t addr,
	     lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t   *pattern = (lm_byte_t *)LM_NULL;
	lm_tchar_t  *mask = (lm_tchar_t *)LM_NULL;

	LM_ASSERT(_LM_ValidProcess(proc) && sig != LM_NULLPTR &&
		  addr != LM_NULLPTR && scansize > 0);

	if (!_LM_ParseSig(sig, &pattern, &mask))
		return match;

	match = LM_PatternScanEx(proc, pattern, mask, addr, scansize);

	LM_FREE(pattern);
	LM_FREE(mask);

	return match;
}

