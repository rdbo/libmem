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

#include "internal.h"

LM_API lm_bool_t LM_CALL
LM_EnumPages(lm_bool_t (LM_CALL *callback)(lm_page_t *ppage,
					   lm_void_t *arg),
	     lm_void_t          *arg)
{
	if (!callback)
		return LM_FALSE;

	return _LM_EnumPages(callback, arg);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_EnumPagesEx(const lm_process_t *pproc,
	       lm_bool_t (LM_CALL *callback)(lm_page_t *ppage,
					     lm_void_t *arg),
	       lm_void_t          *arg)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || !callback)
		return LM_FALSE;

	return _LM_EnumPagesEx(pproc, callback, arg);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetPage(lm_address_t addr,
	   lm_page_t   *pagebuf)
{
	if (addr == LM_ADDRESS_BAD || !pagebuf)
		return LM_FALSE;

	return _LM_GetPage(addr, pagebuf);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetPageEx(const lm_process_t *pproc,
	     lm_address_t        addr,
	     lm_page_t          *pagebuf)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || addr == LM_ADDRESS_BAD || !pagebuf)
		return LM_FALSE;

	return _LM_GetPageEx(pproc, addr, pagebuf);
}

