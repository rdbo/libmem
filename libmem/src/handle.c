#include "internal.h"

#if LM_OS == LM_OS_WIN
LM_PRIVATE HANDLE
_LM_OpenProcess(lm_pid_t pid,
		HANDLE  *hProcess)
{
	LM_ASSERT(pid != LM_PID_BAD && hProcess != LM_NULLPTR);

	if (pid == GetCurrentProcessId()) {
		*hProcess = GetCurrentProcess();
	} else {
		*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

		/* the process is dead, but can still open handles */
		if (*hProcess && GetExitCodeProcess(*hProcess) != STILL_ACTIVE) {
			CloseHandle(*hProcess);
			hProcess = NULL;
		}
	}

	return hProcess;
}

LM_PRIVATE lm_void_t
_LM_CloseProcess(HANDLE *handle)
{
	LM_ASSERT(handle != LM_NULLPTR);

	if (*handle)
		CloseHandle(*handle);

	*handle = NULL;
}
#endif
