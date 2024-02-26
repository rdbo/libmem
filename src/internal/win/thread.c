#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(const lm_process_t *pproc,
		  lm_bool_t (LM_CALL *callback)(lm_thread_t *pthr,
						lm_void_t   *arg),
		  lm_void_t          *arg)
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

/********************************/

LM_PRIVATE lm_bool_t
_LM_GetThread(lm_thread_t *thrbuf)
{
	thrbuf->tid = (lm_tid_t)GetCurrentThreadId();
	return LM_TRUE;
}

/********************************/

LM_PRIVATE lm_pid_t
_LM_GetPidFromThread(const lm_thread_t *pthr)
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
