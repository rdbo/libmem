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

LM_API lm_address_t
LM_DataScan(lm_bytearr_t data,
	    lm_size_t    size,
	    lm_address_t addr,
	    lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t   *ptr;

	if (!data || size == 0 || addr == LM_ADDRESS_BAD || scansize == 0)
		return LM_ADDRESS_BAD;

	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		for (i = 0; check && i < size; ++i) {
			if (ptr[i] != data[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	return match;
}

/********************************/

LM_API lm_address_t
LM_DataScanEx(lm_process_t *pproc,
	      lm_bytearr_t  data,
	      lm_size_t     size,
	      lm_address_t  addr,
	      lm_size_t     scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t   *scanbuf;
	lm_size_t    i, j;
	lm_bool_t    check;

	if (!pproc || !LM_VALID_PROCESS(pproc) || !data || size == 0 || addr == LM_ADDRESS_BAD || scansize == 0 || scansize < size)
		return LM_ADDRESS_BAD;

	scanbuf = (lm_byte_t *)LM_MALLOC(scansize);
	if (!scanbuf)
		return match;

	if (!LM_ReadMemoryEx(pproc, addr, scanbuf, scansize))
		goto FREE_EXIT;

	for (i = 0; i <= scansize - size; ++i) {
		check = LM_TRUE;
		for (j = 0; j < size; ++j) {
			if (scanbuf[i + j] != data[j])
				check = LM_FALSE;
		}

		if (check) {
			match = addr + i;
			break;
		}
	}

FREE_EXIT:
	LM_FREE(scanbuf);

	return match;
}

/********************************/

LM_API lm_address_t
LM_PatternScan(lm_bytearr_t pattern,
	       lm_string_t  mask,
	       lm_address_t addr,
	       lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_size_t    size;
	lm_byte_t   *ptr;

	LM_ASSERT(pattern != LM_NULLPTR && mask != LM_NULLPTR &&
		  addr != LM_ADDRESS_BAD && scansize > 0);

	size = LM_STRLEN(mask);
	if (!size)
		return match;

	for (ptr = (lm_byte_t *)addr;
	     ptr != &((lm_byte_t *)addr)[scansize];
	     ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		for (i = 0; check && i < size; ++i) {
			if (LM_CHKMASK(mask[i]) && ptr[i] != pattern[i])
				check = LM_FALSE;
		}
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	return match;
}

/********************************/

LM_API lm_address_t
LM_PatternScanEx(lm_process_t *pproc,
		 lm_bytearr_t  pattern,
		 lm_string_t   mask,
		 lm_address_t  addr,
		 lm_size_t     scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_size_t    size;
	lm_byte_t   *scanbuf;
	lm_size_t    i, j;
	lm_bool_t    check;

	LM_ASSERT(pproc != LM_NULLPTR &&
		  LM_VALID_PROCESS(pproc) && pattern != LM_NULLPTR &&
		  mask != LM_NULLPTR && addr != LM_ADDRESS_BAD &&
		  scansize > 0);

	size = LM_STRLEN(mask);
	if (!size || scansize < size)
		return match;

	scanbuf = (lm_byte_t *)LM_MALLOC(scansize);
	if (!scanbuf)
		return match;

	if (!LM_ReadMemoryEx(pproc, addr, scanbuf, scansize))
		goto FREE_EXIT;

	for (i = 0; i <= scansize - size; ++i) {
		check = LM_TRUE;
		for (j = 0; j < size; ++j) {
			if (LM_CHKMASK(mask[j]) && scanbuf[i + j] != pattern[j])
				check = LM_FALSE;
		}

		if (check) {
			match = addr + i;
			break;
		}
	}

FREE_EXIT:
	LM_FREE(scanbuf);

	return match;
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_ParseSig(lm_string_t   sig,
	     lm_bytearr_t *ppattern,
	     lm_string_t  *pmask)
{
	lm_bool_t    ret = LM_FALSE;
	lm_byte_t   *pattern = (lm_byte_t *)LM_NULL;
	lm_char_t   *mask = (lm_char_t *)LM_NULL;
	lm_size_t    len = 0;
	lm_char_t   *ptr;
	
	for (ptr = sig; ptr; ptr = LM_STRCHR(ptr, LM_STR(' '))) {
		lm_byte_t  *old_pattern = pattern;
		lm_char_t  *old_mask = mask;
		lm_byte_t   curbyte = 0;
		lm_char_t   curchar = LM_MASK_UNKNOWN;

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

		mask = (lm_char_t *)LM_CALLOC(len + 2, sizeof(lm_char_t));
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
LM_SigScan(lm_string_t  sig,
	   lm_address_t addr,
	   lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_bytearr_t pattern = (lm_byte_t *)LM_NULL;
	lm_string_t  mask = (lm_string_t)LM_NULL;

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
LM_SigScanEx(lm_process_t *pproc,
	     lm_string_t   sig,
	     lm_address_t  addr,
	     lm_size_t     scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t   *pattern = (lm_byte_t *)LM_NULL;
	lm_char_t   *mask = (lm_char_t *)LM_NULL;

	LM_ASSERT(pproc != LM_NULLPTR &&
		  LM_VALID_PROCESS(pproc) && sig != LM_NULLPTR &&
		  addr != LM_ADDRESS_BAD && scansize > 0);

	if (!_LM_ParseSig(sig, &pattern, &mask))
		return match;

	match = LM_PatternScanEx(pproc, pattern, mask, addr, scansize);

	LM_FREE(pattern);
	LM_FREE(mask);

	return match;
}

