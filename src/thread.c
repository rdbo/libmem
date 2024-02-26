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

#include "internal.h"

LM_API lm_bool_t LM_CALL
LM_EnumThreads(lm_bool_t (LM_CALL *callback)(lm_thread_t *pthr,
					     lm_void_t   *arg),
	       lm_void_t          *arg)
{
	lm_process_t proc;

	if (!callback)
		return LM_FALSE;

	if (!LM_GetProcess(&proc))
		return LM_FALSE;

	return LM_EnumThreadsEx(&proc, callback, arg);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_EnumThreadsEx(const lm_process_t *pproc,
		 lm_bool_t (LM_CALL *callback)(lm_thread_t *pthr,
					       lm_void_t   *arg),
		   lm_void_t        *arg)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || !callback)
		return LM_FALSE;

	return _LM_EnumThreadsEx(pproc, callback, arg);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetThread(lm_thread_t *thrbuf)
{
	if (!thrbuf)
		return LM_FALSE;
	return _LM_GetThread(thrbuf);
}

/********************************/

LM_PRIVATE lm_bool_t LM_CALL
_LM_GetThreadExCallback(lm_thread_t *pthr,
			lm_void_t   *arg)
{
	/* get the first thread it found from the target process */
	*(lm_thread_t *)arg = *pthr;
	return LM_FALSE;
}

LM_API lm_bool_t LM_CALL
LM_GetThreadEx(const lm_process_t *pproc,
	       lm_thread_t        *thrbuf)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || !thrbuf)
		return LM_FALSE;

	return LM_EnumThreadsEx(pproc, _LM_GetThreadExCallback, (lm_void_t *)thrbuf);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetThreadProcess(const lm_thread_t *pthr,
		    lm_process_t      *procbuf)
{
	lm_pid_t pid;

	if (!pthr || !LM_VALID_THREAD(pthr))
		return LM_FALSE;

	pid = _LM_GetPidFromThread(pthr);
	if (pid == LM_PID_BAD)
		return LM_FALSE;

	return LM_GetProcessEx(pid, procbuf);
}

