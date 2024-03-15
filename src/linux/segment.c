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
#include "consts.h"
#include <stdio.h>
#include <limits.h>

LM_API lm_bool_t LM_CALL
LM_EnumSegmentsEx(const lm_process_t *process,
                  lm_bool_t (LM_CALL *callback)(lm_segment_t *segment,
						lm_void_t    *arg),
		  lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	char maps_path[PATH_MAX];
	FILE *maps_file;
	long base;
	long end;
	char flags[5];
	lm_segment_t segment;
	size_t i;

	if (!process || !callback)
		return result;

	snprintf(maps_path, sizeof(maps_path), "%s/%d/maps", PROCFS_PATH, process->pid);
	maps_file = fopen(maps_path, "r");
	if (!maps_file)
		return result;

	while (fscanf(maps_file, "%lx-%lx %4s %*[^\n]", &base, &end, flags) == 3) {
		segment.base = (lm_address_t)(unsigned long)base;
		segment.end = (lm_address_t)(unsigned long)end;
		segment.size = segment.end - segment.base;
		segment.prot = LM_PROT_NONE;

		/*
		 * NOTE: We use sizeof(flags) - 1 because we don't need to read the NULL terminator.
		 *       We also don't use %4c as the scanf formatting because it will not skip
		 *       whitespaces.
		 */
		for (i = 0; i < sizeof(flags) - 1; ++i) {
			switch (flags[i]) {
			case 'r':
				segment.prot |= LM_PROT_R;
				break;
			case 'w':
				segment.prot |= LM_PROT_W;
				break;
			case 'x':
				segment.prot |= LM_PROT_X;
				break;
			}
		}

		if (callback(&segment, arg) == LM_FALSE)
			break;
	}

	result = LM_TRUE;
CLOSE_EXIT:
	fclose(maps_file);
	return result;
}
