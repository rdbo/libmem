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
#include <sys/mman.h>



#include <stdio.h>

int
get_os_prot(lm_prot_t prot)
{
	int osprot = PROT_NONE;

	switch (prot) {
	case LM_PROT_X: osprot = PROT_EXEC;
	case LM_PROT_R: osprot = PROT_READ;
	case LM_PROT_W: osprot = PROT_WRITE;
	case LM_PROT_XR: osprot = PROT_EXEC | PROT_READ;
	case LM_PROT_XW: osprot = PROT_EXEC | PROT_WRITE;
	case LM_PROT_RW: osprot = PROT_READ | PROT_WRITE;
	case LM_PROT_XRW: osprot = PROT_EXEC | PROT_READ | PROT_WRITE;
	}
	
	return osprot;
}
