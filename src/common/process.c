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
#include <assert.h>
#include <string.h>

typedef struct {
	lm_process_t *process_out;
	lm_string_t   process_name;
	lm_size_t     len;
} find_pid_t;

lm_bool_t LM_CALL
find_process_callback(lm_process_t *process, lm_void_t *arg)
{
	find_pid_t *parg = (find_pid_t *)arg;
	lm_size_t len;

	assert(process && parg);

	len = strlen(process->path);
	if (len && len >= parg->len) {
		if (!strcmp(&process->path[len - parg->len], parg->process_name)) {
			*(parg->process_out) = *process;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_FindProcess(lm_string_t   process_name,
	       lm_process_t *process_out)

{
	find_pid_t arg;

	if (!process_name || !process_out)
		return LM_FALSE;

	arg.process_out = process_out;
	arg.process_out->pid = LM_PID_BAD;
	arg.process_name = process_name;
	arg.len = strlen(arg.process_name);

	LM_EnumProcesses(find_process_callback, (lm_void_t *)&arg);

	return arg.process_out->pid != LM_PID_BAD ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_GetBits()
{
	return sizeof(void *) * 8;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_IsProcessAlive(const lm_process_t *process)
{
	lm_process_t found_process;
	
	if (!process)
		return LM_FALSE;

	if (!LM_GetProcessEx(process->pid, &found_process))
		return LM_FALSE;

	/* If the process has the same PID and the same start time, it is the same process */
	return found_process.start_time == process->start_time ? LM_TRUE : LM_FALSE;
}
