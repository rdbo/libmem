/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2022    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
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
#if LM_OS != LM_OS_WIN
#	include <dirent.h>
#endif

LM_API lm_bool_t
LM_EnumThreadIds(lm_bool_t(*callback)(lm_tid_t   tid,
				      lm_void_t *arg),
		 lm_void_t *arg)
{
	lm_process_t proc;

	LM_ASSERT(callback != LM_NULLPTR);
	if (!LM_GetProcess(&proc))
		return LM_FALSE;

	return LM_EnumThreadIdsEx(&proc, callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumThreadIdsEx(lm_process_t *pproc,
		    lm_bool_t   (*callback)(lm_tid_t   tid,
					    lm_void_t *arg),
		    lm_void_t    *arg)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	THREADENTRY32 entry;

	hSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD,
		0
	);

	if (hSnap == INVALID_HANDLE_VALUE)
		return ret;

	entry.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnap, &entry)) {
		do {
			lm_tid_t tid;

			if (entry.th32OwnerProcessID !=
			    pproc->pid)
				continue;
					
			tid = (lm_tid_t)entry.th32ThreadID;

			if (callback(tid, arg) == LM_FALSE)
				break;
		} while (Thread32Next(hSnap, &entry));

		ret = LM_TRUE;
	}

	CloseHandle(hSnap);

	return ret;
}
#elif LM_OS == LM_OS_BSD
typedef struct {
	lm_pid_t pid;
	lm_bool_t (*callback)(lm_tid_t tid, lm_void_t *arg);
	lm_void_t *arg;
} _lm_enum_tids_t;

LM_PRIVATE lm_bool_t
_LM_EnumThreadIdsExCallback(lm_process_t *pproc,
			    lm_void_t    *arg)
{
	_lm_enum_tids_t *data = (_lm_enum_tids_t *)arg;
	/* if the given pid owns the current pid, it is its thread */
	if (pproc->ppid == data->pid)
		data->callback((lm_tid_t)pproc->pid, data->arg);
	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumThreadIdsEx(lm_process_t *pproc,
		    lm_bool_t   (*callback)(lm_tid_t   tid,
					    lm_void_t *arg),
		    lm_void_t    *arg)
{
	_lm_enum_tids_t data;
	data.pid = pproc->pid;
	data.callback = callback;
	data.arg = arg;
	return LM_EnumProcesses(_LM_EnumThreadIdsExCallback, (lm_void_t *)&data);
}
#else
LM_PRIVATE lm_bool_t
_LM_EnumThreadIdsEx(lm_process_t *pproc,
		    lm_bool_t   (*callback)(lm_tid_t   tid,
					    lm_void_t *arg),
		    lm_void_t    *arg)
{
	DIR *pdir;
	struct dirent *pdirent;
	lm_char_t task_path[LM_PATH_MAX] = { 0 };

	LM_SNPRINTF(task_path, LM_ARRLEN(task_path),
		    LM_STR("/proc/%d/task"), pproc->pid);

	pdir = opendir(task_path);
	if (!pdir)
		return LM_FALSE;
		
	while ((pdirent = readdir(pdir))) {
		lm_tid_t tid = LM_ATOI(pdirent->d_name);

		if (!tid && LM_STRCMP(pdirent->d_name, "0"))
			continue;

		if (callback(tid, arg) == LM_FALSE)
			break;
	}

	closedir(pdir);

	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_EnumThreadIdsEx(lm_process_t *pproc,
		   lm_bool_t   (*callback)(lm_tid_t   tid,
					   lm_void_t *arg),
		   lm_void_t    *arg)
{
	LM_ASSERT(pproc != LM_NULLPTR && callback != LM_NULLPTR);

	return _LM_EnumThreadIdsEx(pproc, callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_tid_t
_LM_GetThreadId(lm_void_t)
{
	return (lm_tid_t)GetCurrentThreadId();
}
#else
LM_PRIVATE lm_tid_t
_LM_GetThreadId(lm_void_t)
{
	/* the process id and the thread id are the same (threads are also processes) */

	return (lm_tid_t)getpid();
}
#endif

LM_API lm_tid_t
LM_GetThreadId(lm_void_t)
{
	return _LM_GetThreadId();
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_GetThreadIdExCallback(lm_tid_t   tid,
			  lm_void_t *arg)
{
	/* Gets the first thread it finds from the target process */
	*(lm_tid_t *)arg = tid;
	return LM_FALSE;
}

LM_API lm_tid_t
LM_GetThreadIdEx(lm_process_t *pproc)
{
	lm_tid_t tid = LM_TID_BAD;

	LM_ASSERT(pproc != LM_NULLPTR);

	LM_EnumThreadIdsEx(pproc, _LM_GetThreadIdExCallback, (lm_void_t *)&tid);

	return tid;
}

