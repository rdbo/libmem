#include "internal.h"
#if LM_OS != LM_OS_WIN
#	include <dirent.h>
#endif

LM_API lm_bool_t
LM_EnumThreads(lm_bool_t(*callback)(lm_tid_t   tid,
				    lm_void_t *arg),
	       lm_void_t *arg)
{
	lm_bool_t ret;
	lm_process_t proc;

	LM_ASSERT(callback != LM_NULLPTR);	

	if (LM_OpenProcess(&proc)) {
		ret = LM_EnumThreadsEx(proc, callback, arg);
		LM_CloseProcess(&proc);
	}

	return ret;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(lm_process_t proc,
		  lm_bool_t  (*callback)(lm_tid_t   tid,
					 lm_void_t *arg),
		  lm_void_t   *arg)
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
			    proc.pid)
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
} _lm_enum_threads_t;

LM_PRIVATE lm_bool_t
_LM_EnumThreadsExCallback(lm_pid_t   pid,
			  lm_void_t *arg)
{
	_lm_enum_threads_t *data = (_lm_enum_threads_t *)arg;
	/* if the given pid owns the current pid, it is its thread */
	if (LM_GetParentIdEx(pid) == data->pid)
		data->callback((lm_tid_t)pid, data->arg);
	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(lm_process_t proc,
		  lm_bool_t  (*callback)(lm_tid_t   tid,
					 lm_void_t *arg),
		  lm_void_t   *arg)
{
	_lm_enum_threads_t data;
	data.pid = proc.pid;
	data.callback = callback;
	data.arg = arg;
	return LM_EnumProcesses(_LM_EnumThreadsExCallback, (lm_void_t *)&data);
}
#else
LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(lm_process_t proc,
		  lm_bool_t  (*callback)(lm_tid_t   tid,
					 lm_void_t *arg),
		  lm_void_t   *arg)
{
	DIR *pdir;
	struct dirent *pdirent;
	lm_tchar_t task_path[LM_PATH_MAX] = { 0 };

	LM_SNPRINTF(task_path, LM_ARRLEN(task_path),
		    LM_STR("/proc/%d/task"), proc.pid);

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
LM_EnumThreadsEx(lm_process_t proc,
		 lm_bool_t  (*callback)(lm_tid_t   tid,
					lm_void_t *arg),
		 lm_void_t   *arg)
{
	LM_ASSERT(LM_VALID_PROCESS(proc) && callback != LM_NULLPTR);

	return _LM_EnumThreadsEx(proc, callback, arg);
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
	return (lm_tid_t)LM_GetProcessId();
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
LM_GetThreadIdEx(lm_process_t proc)
{
	lm_tid_t tid = LM_TID_BAD;

	LM_ASSERT(LM_VALID_PROCESS(proc));

	LM_EnumThreadsEx(proc, _LM_GetThreadIdExCallback, (lm_void_t *)&tid);

	return tid;
}

