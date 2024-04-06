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
#include <memory.h>
#include <assert.h>

LM_API lm_address_t LM_CALL
LM_DataScan(lm_bytearray_t data,
	    lm_size_t      datasize,
	    lm_address_t   address,
	    lm_size_t      scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t *ptr;
	lm_size_t i;

	if (!data || datasize == 0 || address == LM_ADDRESS_BAD || scansize < datasize)
		return match;

	for (ptr = (lm_byte_t *)address; ptr != (lm_byte_t *)(address + scansize); ptr = &ptr[1]) {
		for (i = 0; i < datasize; ++i) {
			if (ptr[i] != data[i])
				break;
		}

		if (i == datasize) {
			/* Loop didn't break, so all bytes are the same */
			match = (lm_address_t)ptr;
			break;
		}
	}

	return match;
}

/********************************/

LM_API lm_address_t LM_CALL
LM_DataScanEx(const lm_process_t *process,
	      lm_bytearray_t      data,
	      lm_size_t           datasize,
	      lm_address_t        address,
	      lm_size_t           scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	void *scanbuf;

	if (!process || !data || datasize == 0 || address == LM_ADDRESS_BAD || scansize < datasize)
		return match;

	scanbuf = malloc(scansize);
	if (!scanbuf)
		return match;

	if (LM_ReadMemoryEx(process, address, scanbuf, scansize) == 0)
		goto CLEAN_EXIT;

	match = LM_DataScan(data, datasize, (lm_address_t)scanbuf, scansize);
	if (match != LM_ADDRESS_BAD) {
		/* Resolve pointer from current process to the remote process */
		match -= (lm_address_t)scanbuf;
		match += address;
	}

CLEAN_EXIT:
	free(scanbuf);
	return match;
}

/********************************/

LM_API lm_address_t LM_CALL
LM_PatternScan(lm_bytearray_t pattern,
	       lm_string_t    mask,
	       lm_address_t   address,
	       lm_size_t      scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_size_t masklen;
	lm_byte_t *ptr;
	lm_size_t i;
	
	if (!pattern || !mask || address == LM_ADDRESS_BAD)
		return match;

	masklen = strlen(mask);
	if (masklen == 0 || scansize < masklen)
		return match;

	for (ptr = (lm_byte_t *)address; ptr != (lm_byte_t *)(address + scansize); ptr = &ptr[1]) {
		for (i = 0; i < masklen; ++i) {
			if (mask[i] != '?' && pattern[i] != ptr[i])
				break;
		}

		if (i == masklen) {
			match = (lm_address_t)ptr;
			break;
		}
	}

	return match;
}

/********************************/

LM_API lm_address_t LM_CALL
LM_PatternScanEx(const lm_process_t *process,
		 lm_bytearray_t      pattern,
		 lm_string_t         mask,
		 lm_address_t        address,
		 lm_size_t           scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_size_t masklen;
	void *scanbuf;

	if (!process || !pattern || !mask || address == LM_ADDRESS_BAD)
		return match;

	masklen = strlen(mask);
	if (masklen == 0 || scansize < masklen)
		return match;

	scanbuf = malloc(scansize);
	if (!scanbuf)
		return match;

	if (LM_ReadMemoryEx(process, address, scanbuf, scansize) == 0)
		goto CLEAN_EXIT;

	match = LM_PatternScan(pattern, mask, (lm_address_t)scanbuf, scansize);
	if (match != LM_ADDRESS_BAD) {
		/* Resolve pointer from current process to the remote process */
		match -= (lm_address_t)scanbuf;
		match += address;
	}

CLEAN_EXIT:
	free(scanbuf);
	return match;
}

/********************************/

lm_bool_t
sig_to_pattern(lm_string_t signature, lm_byte_t **pattern_out, lm_char_t **mask_out)
{
	lm_byte_t *pattern = (lm_byte_t *)NULL;
	lm_char_t *mask = (lm_char_t *)NULL;
	lm_char_t *ptr;
	size_t bytecount = 0;
	void *alloc;
	lm_char_t *endptr;

	assert(signature && pattern_out && mask_out);

	/* NOTE: There must be exactly 1 space between the bytes. Any more than that can result in bad convertion */
	for (ptr = (lm_char_t *)signature; ptr && *ptr; ptr = endptr, ++bytecount) {
		if (alloc = realloc(pattern, (bytecount + 1) * sizeof(lm_byte_t))) {
			pattern = (lm_byte_t *)alloc;
		} else {
			free(pattern);
			if (mask) free(mask);
			return LM_FALSE;
		}

		if (alloc = realloc(mask, (bytecount + 2) * sizeof(lm_char_t))) {
			mask = (lm_char_t *)alloc;
		} else {
			free(mask);
			free(pattern);
			return LM_FALSE;
		}

		pattern[bytecount] = strtol(ptr, &endptr, 16);
		if (pattern[bytecount] == 0 && ptr == endptr) {
			endptr = strchr(&ptr[1], ' ');
			mask[bytecount] = '?';
			mask[bytecount + 1] = '\0';
		} else {
			mask[bytecount] = 'x';
			mask[bytecount + 1] = '\0';
		}
	}

	if (bytecount == 0)
		return LM_FALSE;

	*pattern_out = pattern;
	*mask_out = mask;
	return LM_TRUE;
}

LM_API lm_address_t LM_CALL
LM_SigScan(lm_string_t  signature,
	   lm_address_t address,
	   lm_size_t    scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t *pattern;
	lm_char_t *mask;

	if (!signature || address == LM_ADDRESS_BAD || scansize == 0)
		return match;
	
	if (!sig_to_pattern(signature, &pattern, &mask))
		return match;

	/* TODO: Delete */
	printf("Parsed signature %s into:\n", signature);
	for (size_t i = 0; i < strlen(mask); ++i) {
		printf("%hhx", (unsigned char)pattern[i]);
	}
	printf("\n");
	printf("%s\n", mask);

	match = LM_PatternScan(pattern, mask, address, scansize);

	free(pattern);
	free(mask);

	return match;
}

/********************************/

LM_API lm_address_t LM_CALL
LM_SigScanEx(const lm_process_t *process,
	     lm_string_t         signature,
	     lm_address_t        address,
	     lm_size_t           scansize)
{
	lm_address_t match = LM_ADDRESS_BAD;
	lm_byte_t *pattern;
	lm_char_t *mask;

	if (!process || !signature || address == LM_ADDRESS_BAD || scansize == 0)
		return match;
	
	if (!sig_to_pattern(signature, &pattern, &mask))
		return match;

	match = LM_PatternScanEx(process, pattern, mask, address, scansize);

	free(pattern);
	free(mask);

	return match;
}
