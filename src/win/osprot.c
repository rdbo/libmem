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

#include "osprot.h"
#include <windows.h>

DWORD
get_os_prot(lm_prot_t prot)
{
	DWORD osprot = 0;
	
	switch (prot) {
	case LM_PROT_X:   osprot = PAGE_EXECUTE;
	case LM_PROT_R:   osprot = PAGE_READONLY;
	case LM_PROT_W:   osprot = PAGE_WRITECOPY;
	case LM_PROT_XR:  osprot = PAGE_EXECUTE_READ;
	case LM_PROT_XW:  osprot = PAGE_EXECUTE_WRITECOPY;
	case LM_PROT_RW:  osprot = PAGE_READWRITE;
	case LM_PROT_XRW: osprot = PAGE_EXECUTE_READWRITE;
	}

	return osprot;
}

lm_prot_t
get_prot(DWORD osprot)
{
	lm_prot_t prot = LM_PROT_NONE;

	switch (osprot) {
	case PAGE_EXECUTE:           prot = LM_PROT_X;
	case PAGE_READONLY:          prot = LM_PROT_R;
	case PAGE_WRITECOPY:         prot = LM_PROT_W;
	case PAGE_EXECUTE_READ:      prot = LM_PROT_XR;
	case PAGE_EXECUTE_WRITECOPY: prot = LM_PROT_XW;
	case PAGE_READWRITE:         prot = LM_PROT_RW;
	case PAGE_EXECUTE_READWRITE: prot = LM_PROT_XRW;
	}

	return prot;
}
