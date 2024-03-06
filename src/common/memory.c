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

LM_API lm_size_t LM_CALL
LM_ReadMemory(lm_address_t source,
	      lm_byte_t   *dest,
	      lm_size_t    size)
{
	size_t i = 0;

	if (source == LM_ADDRESS_BAD || !dest || size == 0)
		return i;
	
	for (; i < size; ++i)
		dest[i] = *(lm_byte_t *)(source + i);

	return i;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_WriteMemory(lm_address_t   dest,
	       lm_bytearray_t source,
	       lm_size_t      size)
{
	size_t i = 0;

	if (dest == LM_ADDRESS_BAD || !source || size == 0)
		return i;
	
	for (i = 0; i < size; ++i)
		*(lm_byte_t *)(dest + i) = source[i];

	return i;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_SetMemory(lm_address_t dest,
	     lm_byte_t    byte,
	     lm_size_t    size)
{
	size_t i = 0;

	if (dest == LM_ADDRESS_BAD || size == 0)
		return i;
	
	for (; i < size; ++i)
		*(lm_byte_t *)(dest + i) = byte;

	return i;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_SetMemoryEx(const lm_process_t *process,
	       lm_address_t        dest,
	       lm_byte_t           byte,
	       lm_size_t           size)
{
	lm_size_t wrsize = 0;
	lm_byte_t *buf;

	if (!process || dest == LM_ADDRESS_BAD || size == 0)
		return wrsize;

	/* Put all the content that will be written in a buffer
	 * to avoid running multiple writes to the target process */
	buf = (lm_byte_t *)malloc(size);
	if (!buf)
		return wrsize;
	if (LM_SetMemory((lm_address_t)buf, byte, size) != size)
		goto FREE_EXIT;

	wrsize = LM_WriteMemoryEx(process, dest, buf, size);

FREE_EXIT:
	free(buf);
	return wrsize;
}
