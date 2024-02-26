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

LM_PRIVATE lm_size_t
_LM_GetNameFromPath(lm_char_t *path,
		    lm_char_t *namebuf,
		    lm_size_t  maxlen)
{
	lm_char_t *name;
	lm_size_t   len = 0;

	name = LM_STRRCHR(path, LM_PATH_SEP);
	if (!name) {
		namebuf[0] = LM_STR('\x00');
		return len;
	}

	name = &name[1]; /* skip path separator */

	len = LM_STRLEN(name);
	if (len >= maxlen)
		len = maxlen - 1;

	LM_STRNCPY(namebuf, name, len);
	namebuf[len] = LM_STR('\x00');
	
	return len;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *pproc,
					       lm_void_t    *arg),
		 lm_void_t          *arg)
{
	if (!callback)
		return LM_FALSE;

	return _LM_EnumProcesses(callback, arg);
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_GetProcess(lm_process_t *procbuf)
{
	procbuf->pid = _LM_GetProcessId();
	procbuf->ppid = _LM_GetParentId();

	if (!_LM_GetProcessPath(procbuf->path, LM_ARRLEN(procbuf->path)))
		return LM_FALSE;

	if (!_LM_GetNameFromPath(procbuf->path, procbuf->name, LM_ARRLEN(procbuf->name)))
		return LM_FALSE;

	procbuf->start_time = _LM_GetProcessStartTime(procbuf->pid);
	if (procbuf->start_time == LM_TIME_BAD)
		return LM_FALSE;

	procbuf->bits = LM_BITS;
	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_GetProcess(lm_process_t *procbuf)
{
	static lm_process_t self_proc = {
		LM_PID_BAD, LM_PID_BAD, 0, LM_TIME_BAD, "", ""
	};

	if (!procbuf) {
		return LM_FALSE;
	}

	if (self_proc.pid != LM_PID_BAD) {
		*procbuf = self_proc;
		return LM_TRUE;
	}

	if (!_LM_GetProcess(&self_proc)) {
		self_proc.pid = LM_PID_BAD;
		return LM_FALSE;
	}

	*procbuf = self_proc;

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *procbuf)
{
	if (pid == LM_PID_BAD || !procbuf)
		return LM_FALSE;

	procbuf->pid = pid;
	procbuf->ppid = _LM_GetParentIdEx(pid);
	if (procbuf->ppid == LM_PID_BAD)
		return LM_FALSE;
	if (!_LM_GetProcessPathEx(procbuf->pid, procbuf->path, LM_ARRLEN(procbuf->path)))
		return LM_FALSE;
	if (!_LM_GetNameFromPath(procbuf->path, procbuf->name, LM_ARRLEN(procbuf->name)))
		return LM_FALSE;
	procbuf->start_time = _LM_GetProcessStartTime(procbuf->pid);
	if (procbuf->start_time == LM_TIME_BAD)
		return LM_FALSE;

	/* TODO: Unify different '_LM_GetProcessBitsEx' */
#	if LM_OS == LM_OS_WIN
	procbuf->bits = _LM_GetProcessBitsEx(procbuf->pid);
#	else
	procbuf->bits = _LM_GetProcessBitsEx(procbuf->path);
#	endif

	return LM_TRUE;
}

/********************************/

typedef struct {
	lm_process_t *procbuf;
	lm_string_t   procstr;
	lm_size_t     len;
} _lm_find_pid_t;

LM_PRIVATE lm_bool_t LM_CALL
_LM_FindProcessCallback(lm_process_t *pproc,
			lm_void_t    *arg)
{
	_lm_find_pid_t   *parg = (_lm_find_pid_t *)arg;
	lm_size_t len;

	len = LM_STRLEN(pproc->path);
	if (len && len >= parg->len) {
		if (!LM_STRCMP(&pproc->path[len - parg->len], parg->procstr)) {
			*(parg->procbuf) = *pproc;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_FindProcess(lm_string_t   procstr,
	       lm_process_t *procbuf)
{
	_lm_find_pid_t arg;

	if (!procstr || !procbuf)
		return LM_FALSE;

	arg.procbuf = procbuf;
	arg.procbuf->pid = LM_PID_BAD;
	arg.procstr = procstr;
	arg.len = LM_STRLEN(arg.procstr);

	LM_EnumProcesses(_LM_FindProcessCallback, (lm_void_t *)&arg);

	return arg.procbuf->pid != LM_PID_BAD ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_IsProcessAlive(const lm_process_t *pproc)
{
	if (!pproc || !LM_VALID_PROCESS(pproc))
		return LM_FALSE;

	/* If the process has the same PID and the same start time, it is the same process */
	return _LM_GetProcessStartTime(pproc->pid) == pproc->start_time ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_GetSystemBits(lm_void_t)
{
	lm_size_t bits = LM_BITS;

	_LM_GetSystemBits(&bits);

	return bits;
}
