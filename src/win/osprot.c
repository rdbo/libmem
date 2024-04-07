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
	case LM_PROT_X:   osprot = PAGE_EXECUTE; break;
	case LM_PROT_R:   osprot = PAGE_READONLY; break;
	case LM_PROT_W:   osprot = PAGE_WRITECOPY; break;
	case LM_PROT_XR:  osprot = PAGE_EXECUTE_READ; break;
	case LM_PROT_XW:  osprot = PAGE_EXECUTE_WRITECOPY; break;
	case LM_PROT_RW:  osprot = PAGE_READWRITE; break;
	case LM_PROT_XRW: osprot = PAGE_EXECUTE_READWRITE; break;
	}

	return osprot;
}

lm_prot_t
get_prot(DWORD osprot)
{
	lm_prot_t prot = LM_PROT_NONE;

	switch (osprot) {
	case PAGE_EXECUTE:           prot = LM_PROT_X; break;
	case PAGE_READONLY:          prot = LM_PROT_R; break;
	case PAGE_WRITECOPY:         prot = LM_PROT_W; break;
	case PAGE_EXECUTE_READ:      prot = LM_PROT_XR; break;
	case PAGE_EXECUTE_WRITECOPY: prot = LM_PROT_XW; break;
	case PAGE_READWRITE:         prot = LM_PROT_RW; break;
	case PAGE_EXECUTE_READWRITE: prot = LM_PROT_XRW; break;
	}

	return prot;
}
