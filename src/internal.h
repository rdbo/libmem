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

#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem/libmem.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include "utils.h"

#if LM_OS == LM_OS_WIN
#	include "internal/win/_internal.h"
#else
#	include "internal/unix/_internal.h"
#	if LM_OS == LM_OS_BSD
#		include "internal/bsd/_internal.h"
#	else
#		include "internal/linux/_internal.h"
#	endif
#endif

/* Internal wrappers used in functions that are different across platforms */
LM_PRIVATE lm_bool_t
_LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *pproc,
						lm_void_t    *arg),
		   lm_void_t         *arg);

LM_PRIVATE lm_void_t
_LM_GetSystemBits(lm_size_t *bits);

/********************************/

LM_PRIVATE lm_bool_t
_LM_EnumPages(lm_bool_t (LM_CALL *callback)(lm_page_t *ppage,
					    lm_void_t *arg),
	      lm_void_t          *arg);

LM_PRIVATE lm_bool_t
_LM_EnumPagesEx(const lm_process_t *pproc,
		lm_bool_t (LM_CALL *callback)(lm_page_t *ppage,
					      lm_void_t *arg),
		lm_void_t          *arg);

LM_PRIVATE lm_bool_t
_LM_GetPage(lm_address_t addr,
	    lm_page_t   *pagebuf);
#endif
