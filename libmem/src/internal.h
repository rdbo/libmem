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

#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem/libmem.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

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

LM_PRIVATE lm_pid_t
_LM_GetProcessId(lm_void_t);

LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t);

LM_PRIVATE lm_pid_t
_LM_GetParentIdEx(lm_pid_t pid);

LM_PRIVATE lm_size_t
_LM_GetProcessPath(lm_char_t *pathbuf,
		   lm_size_t  maxlen);

LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t   pid,
		     lm_char_t *pathbuf,
		     lm_size_t  maxlen);

LM_PRIVATE lm_size_t
_LM_GetNameFromPath(lm_char_t *path,
		    lm_char_t *namebuf,
		    lm_size_t  maxlen);

LM_PRIVATE lm_prot_t
_LM_GetRealProt(lm_prot_t prot); /* turn libmem flags into OS-specific flags */

LM_PRIVATE lm_prot_t
_LM_GetProt(lm_prot_t prot); /* turn OS-specific flags into libmem flags */
#endif
