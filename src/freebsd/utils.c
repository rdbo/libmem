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

lm_char_t *
get_process_cmdline(struct procstat *procstat, struct kinfo_proc *proc)
{
	lm_char_t *buf = NULL;
	lm_char_t *ptr;
	size_t length = 0;
	size_t i;
	char **args;
	size_t size;

	args = procstat_getargv(procstat, kipp, 0);

	buf = calloc(sizeof(lm_char_t), length + sizeof(proc->ki_comm) + 1);
	if (!buf)
		return NULL;
	strncpy(&buf[length], proc->ki_comm, sizeof(proc->ki_comm));
	length += sizeof(proc->ki_comm);

	length = strlen(buf); // TODO: check if ki_comm is already null terminated and then remove this line and resize the buffer.

	for (i = 0; args[i] != NULL; ++i) {
		size = strlen(args[i]);
		ptr = buf;
		buf = realloc(buf, (length + 1 + size + 1) * sizeof(lm_char_t))
		if (!buf) {
			free(ptr);
			return NULL;
		}

		buf[length] = ' ';
		length += 1;
		
		strncpy(&buf[length], args[i], size);
		length += size;
	}

	buf[length] = '\0';

	return buf;
}
