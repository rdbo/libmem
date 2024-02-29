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

LM_API lm_bool_t LM_CALL
LM_EnumThreads(lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					     lm_void_t   *arg),
	       lm_void_t          *arg)
{
	lm_process_t process;

	if (!callback)
		return LM_FALSE;

	if (!LM_GetProcess(&process))
		return LM_FALSE;

	return LM_EnumThreadsEx(&process, callback, arg);
}

/********************************/

lm_bool_t LM_CALL
get_thread_callback(lm_thread_t *thread, lm_void_t *arg)
{
	assert(thread != NULL && arg != NULL);
	
	/* Get the first thread found from the target process */
	*(lm_thread_t *)arg = *thread;
	return LM_FALSE;
}

LM_API lm_bool_t LM_CALL
LM_GetThreadEx(const lm_process_t *process,
	       lm_thread_t        *thread_out)
{
	if (!process || !thread_out)
		return LM_FALSE;

	return LM_EnumThreadsEx(process, get_thread_callback, (lm_void_t *)thread_out);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetThreadProcess(const lm_thread_t *thread,
		    lm_process_t      *process_out)
{
	if (!thread || !process_out)
		return LM_FALSE;

	return LM_GetProcessEx(thread->owner_pid, process_out);
}
