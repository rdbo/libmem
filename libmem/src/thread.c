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
LM_EnumThreads(lm_bool_t(*callback)(lm_thread_t *pthr,
				    lm_void_t   *arg),
		 lm_void_t *arg)
{
	lm_process_t proc;

	if (!callback)
		return LM_FALSE;

	if (!LM_GetProcess(&proc))
		return LM_FALSE;

	return LM_EnumThreadsEx(&proc, callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(lm_process_t *pproc,
		  lm_bool_t   (*callback)(lm_thread_t *pthr,
					  lm_void_t   *arg),
		  lm_void_t    *arg)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	THREADENTRY32 entry;
	lm_thread_t thread;

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

			thread.tid = (lm_tid_t)entry.th32ThreadID;

			if (callback(&thread, arg) == LM_FALSE)
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
	lm_bool_t (*callback)(lm_thread_t *pthr, lm_void_t *arg);
	lm_void_t *arg;
} _lm_enum_tids_t;

LM_PRIVATE lm_bool_t
_LM_EnumThreadsExCallback(lm_process_t *pproc,
			  lm_void_t    *arg)
{
	_lm_enum_tids_t *data = (_lm_enum_tids_t *)arg;
	lm_thread_t thread;
	/* if the given pid owns the current pid, it is its thread */
	if (pproc->ppid == data->pid) {
		thread.tid = (lm_tid_t)pproc->pid;
		if (!data->callback(&thread, data->arg))
			return LM_FALSE;
	}
	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(lm_process_t *pproc,
		  lm_bool_t   (*callback)(lm_thread_t *pthr,
					  lm_void_t   *arg),
		  lm_void_t    *arg)
{
	_lm_enum_tids_t data;
	data.pid = pproc->pid;
	data.callback = callback;
	data.arg = arg;
	return LM_EnumProcesses(_LM_EnumThreadsExCallback, (lm_void_t *)&data);
}
#else
LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(lm_process_t *pproc,
		  lm_bool_t   (*callback)(lm_thread_t *pthr,
					  lm_void_t   *arg),
		  lm_void_t    *arg)
{
	DIR *pdir;
	struct dirent *pdirent;
	lm_char_t task_path[LM_PATH_MAX] = { 0 };
	lm_thread_t thread;

	LM_SNPRINTF(task_path, LM_ARRLEN(task_path),
		    LM_STR("/proc/%d/task"), pproc->pid);

	pdir = opendir(task_path);
	if (!pdir)
		return LM_FALSE;
		
	while ((pdirent = readdir(pdir))) {
		thread.tid = LM_ATOI(pdirent->d_name);

		if (!thread.tid && LM_STRCMP(pdirent->d_name, "0"))
			continue;

		if (!callback(&thread, arg))
			break;
	}

	closedir(pdir);

	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_EnumThreadsEx(lm_process_t *pproc,
		 lm_bool_t   (*callback)(lm_thread_t *pthr,
					 lm_void_t   *arg),
		   lm_void_t  *arg)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || !callback)
		return LM_FALSE;

	return _LM_EnumThreadsEx(pproc, callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_GetThread(lm_thread_t *thrbuf)
{
	thrbuf->tid = (lm_tid_t)GetCurrentThreadId();
	return LM_TRUE;
}
#else
LM_PRIVATE lm_bool_t
_LM_GetThread(lm_thread_t *thrbuf)
{
	/* the process id and the thread id are the same (threads are also processes) */
	thrbuf->tid = (lm_tid_t)getpid();
	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_GetThread(lm_thread_t *thrbuf)
{
	if (!thrbuf)
		return LM_FALSE;
	return _LM_GetThread(thrbuf);
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_GetThreadExCallback(lm_thread_t *pthr,
			lm_void_t   *arg)
{
	/* get the first thread it found from the target process */
	*(lm_thread_t *)arg = *pthr;
	return LM_FALSE;
}

LM_API lm_bool_t
LM_GetThreadEx(lm_process_t *pproc,
	       lm_thread_t  *thrbuf)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || !thrbuf)
		return LM_FALSE;

	return LM_EnumThreadsEx(pproc, _LM_GetThreadExCallback, (lm_void_t *)thrbuf);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_pid_t
_LM_GetPidFromThread(lm_thread_t *pthr)
{
	lm_pid_t pid = LM_PID_BAD;
	HANDLE hThread;
	if (!_LM_OpenThr(pthr->tid, &hThread))
		return pid;

	pid = (lm_pid_t)GetProcessIdOfThread(hThread);
	if (!pid)
		pid = LM_PID_BAD;

	return pid;

}
#else
LM_PRIVATE lm_pid_t
_LM_GetPidFromThread(lm_thread_t *pthr)
{
	return (lm_pid_t)pthr->tid;
}
#endif

LM_API lm_bool_t
LM_GetThreadProcess(lm_thread_t  *pthr,
		    lm_process_t *procbuf)
{
	lm_pid_t pid;

	if (!pthr || !LM_VALID_THREAD(pthr))
		return LM_FALSE;

	pid = _LM_GetPidFromThread(pthr);
	if (pid == LM_PID_BAD)
		return LM_FALSE;

	return LM_GetProcessEx(pid, procbuf);
}

