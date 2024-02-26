#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *pproc,
						lm_void_t    *arg),
		   lm_void_t         *arg)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	PROCESSENTRY32 entry;
	lm_process_t proc;
	lm_size_t len;
		
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return ret;

	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &entry)) {
		do {
			proc.pid = (lm_pid_t)entry.th32ProcessID;
			if (proc.pid == LM_PID_BAD)
				continue;

			proc.ppid = (lm_pid_t)entry.th32ParentProcessID;
			/* OBS: The 'szExeFile' member of the 'PROCESSENTRY32'
			 * struct represents the name of the process, not the
			 * full path of the executable.
			 * Source: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32 */
			if (!_LM_GetProcessPathEx(proc.pid, proc.path, LM_ARRLEN(proc.path)))
				continue;

			proc.start_time = _LM_GetProcessStartTime(proc.pid);
			if (proc.start_time == LM_TIME_BAD)
				continue;

			len = LM_STRLEN(entry.szExeFile);
			if (len >= LM_ARRLEN(proc.name))
				len = LM_ARRLEN(proc.name) - 1;

			LM_STRNCPY(proc.name, entry.szExeFile, len);
			proc.name[len] = LM_STR('\x00');
			proc.bits = _LM_GetProcessBitsEx(proc.pid);

			if (callback(&proc, arg) == LM_FALSE)
				break;
		} while (Process32Next(hSnap, &entry));

		ret = LM_TRUE;
	}

	CloseHandle(hSnap);
	
	return ret;
}

/********************************/

LM_PRIVATE lm_void_t
_LM_GetSystemBits(lm_size_t *bits)
{
	SYSTEM_INFO sysinfo = { 0 };

	GetNativeSystemInfo(&sysinfo);
	switch (sysinfo.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
	case PROCESSOR_ARCHITECTURE_ARM64:
		*bits = 64;
		break;
	}
}
