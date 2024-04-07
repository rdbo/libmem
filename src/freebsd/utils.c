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

#include "utils.h"
#include <assert.h>

lm_time_t
get_process_start_time(struct kinfo_proc *proc)
{
	assert(proc != NULL);
	
	/* Turn the seconds and the microseconds from the 'struct timeval' into milliseconds */
	return (lm_time_t)((proc->ki_start.tv_sec * 1000) + (proc->ki_start.tv_usec / 1000.0L));
}
