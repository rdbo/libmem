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
#include <windows.h>
#include <winutils/winutils.h>

LM_API lm_bool_t LM_CALL
LM_EnumSegmentsEx(const lm_process_t *process,
                  lm_bool_t (LM_CALL *callback)(lm_segment_t *segment,
						lm_void_t    *arg),
		  lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	HANDLE hproc;
	lm_address_t address;
	MEMORY_BASIC_INFORMATION meminfo;
	lm_segment_t segment;

	hproc = open_process(process->pid, PROCESS_QUERY_INFORMATION);
	if (!hproc)
		return result;

	/* TODO: Add fix for 32 bit processes enumerating 64 bit target processes (avoid address overflow) */
	for (address = 0;
	     VirtualQueryEx(hproc, address, &meminfo, sizeof(meminfo)) > 0;
	     address += meminfo.RegionSize) {
		/* Skip unallocated regions */
		if (meminfo.State == MEM_FREE)
			continue;

		segment.base = (lm_address_t)meminfo.BaseAddress;
		segment.size = (lm_size_t)meminfo.RegionSize;
		segment.end = segment.base + segment.size;

		if (callback(&segment, arg) == LM_FALSE)
			break;
	}

	result = LM_TRUE;
CLOSE_EXIT:
	close_handle(hproc);
	return result;
}
