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

typedef struct {
	lm_address_t  address;
	lm_segment_t *segment_out;
} find_segment_t;

lm_bool_t LM_CALL
find_segment_callback(lm_segment_t *segment, lm_void_t *arg)
{
	find_segment_t *parg = (find_segment_t *)arg;
	
	if (parg->address >= segment->base && parg->address < segment->end) {
		*parg->segment_out = *segment;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_FindSegment(lm_address_t  address,
	       lm_segment_t *segment_out)
{
	find_segment_t parg;

	if (address == LM_ADDRESS_BAD || !segment_out)
		return LM_FALSE;

	segment_out->base = LM_ADDRESS_BAD;
	parg.address = address;
	parg.segment_out = segment_out;

	if (!LM_EnumSegments(find_segment_callback, (lm_void_t *)&parg))
		return LM_FALSE;

	return segment_out->base != LM_ADDRESS_BAD ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_FindSegmentEx(const lm_process_t *process,
		 lm_address_t        address,
		 lm_segment_t       *segment_out)
{
	find_segment_t parg;

	if (address == LM_ADDRESS_BAD || !segment_out)
		return LM_FALSE;

	segment_out->base = LM_ADDRESS_BAD;
	parg.address = address;
	parg.segment_out = segment_out;

	if (!LM_EnumSegmentsEx(process, find_segment_callback, (lm_void_t *)&parg))
		return LM_FALSE;

	return segment_out->base != LM_ADDRESS_BAD ? LM_TRUE : LM_FALSE;
}
