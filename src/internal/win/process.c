#include "internal.h"

LM_PRIVATE lm_time_t
_LM_FiletimeToTime(FILETIME *ft)
{
	lm_uint64_t time;

	/* copy FILETIME to uint64 */
	((lm_uint32_t *)&time)[1] = ft->dwLowDateTime;
	((lm_uint32_t *)&time)[0] = ft->dwHighDateTime;

	/* convert to seconds (FILETIME has a 100ns accuracy) */
	time = time / 10000000;

	return (lm_time_t)time;	
}

LM_PRIVATE lm_time_t
_LM_GetProcessStartTime(lm_pid_t pid)
{
	/*
	 * WARNING: Unsupported APIs
	 *  - NtQuerySystemInformation: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
	 */

	lm_time_t start_time = LM_TIME_BAD;
	SYSTEM_TIMEOFDAY_INFORMATION time;
	lm_time_t last_boot;
	HANDLE hProcess;
	FILETIME filetime;
	FILETIME tmp;
	lm_time_t creation_time;

	/* Get the system last boot time */
	if (NtQuerySystemInformation(SystemTimeOfDayInformation, &time, sizeof(time), NULL) != STATUS_SUCCESS)
		return start_time;

	last_boot = _LM_FiletimeToTime((FILETIME *)&time);
	if (!_LM_OpenProc(pid, &hProcess))
		return start_time;

	/* Calculate process start time relative to boot time */
	if (GetProcessTimes(hProcess, &filetime, &tmp, &tmp, &tmp)) {
		creation_time = _LM_FiletimeToTime(&filetime);
		start_time = creation_time - last_boot;
	}

	_LM_CloseProc(&hProcess);

	return start_time;
}

/********************************/

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

LM_PRIVATE lm_pid_t
_LM_GetProcessId(lm_void_t)
{
	return (lm_pid_t)GetCurrentProcessId();
}

/********************************/

LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t)
{
	return _LM_GetParentIdEx(_LM_GetProcessId());
}

/********************************/

LM_PRIVATE lm_pid_t
_LM_GetParentIdEx(lm_pid_t pid)
{
	lm_pid_t ppid = LM_PID_BAD;
	HANDLE hSnap;
	
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return ppid;

	PROCESSENTRY32 entry;

	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &entry)) {
		do {
			lm_pid_t curpid = (lm_pid_t)(
				entry.th32ProcessID
			);

			if (curpid == pid) {
				ppid = (lm_pid_t)(
				      entry.th32ParentProcessID
				);

				break;
			}
		} while (Process32Next(hSnap, &entry));
	}

	CloseHandle(hSnap);
	return ppid;
}

/********************************/

LM_PRIVATE lm_size_t
_LM_GetProcessPath(lm_char_t *pathbuf,
		   lm_size_t  maxlen)
{
	lm_size_t len = 0;

	HMODULE hModule = GetModuleHandle(NULL);
	if (!hModule)
		return len;

	len = (lm_size_t)GetModuleFileName(hModule, pathbuf, maxlen);
	if (len >= maxlen)
		len = maxlen - 1;

	pathbuf[len] = LM_STR('\x00');
	return len;
}

/********************************/

LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t   pid,
		     lm_char_t *pathbuf,
		     lm_size_t  maxlen)
{
	lm_size_t len = 0;
	HANDLE hProcess;
	
	if (!_LM_OpenProc(pid, &hProcess))
		return len;

	len = (lm_size_t)GetModuleFileNameEx(hProcess, NULL,
					     pathbuf, maxlen);

	/* From:
	 *
	 * "[out] lpFilename
	 * A pointer to a buffer that receives the fully
	 * qualified path to the module. If the size of the
	 * file name is larger than the value of the nSize
	 * parameter, the function succeeds but the file name
	 * is truncated and null-terminated."
	 *
	 * It is not specified if it is null terminated when
	 * the value of nSize is smaller than the path
	 */

	if (len >= maxlen)
		len = maxlen - 1;

	pathbuf[len] = LM_STR('\x00');

	_LM_CloseProc(&hProcess);

	return len;
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

/********************************/

LM_PRIVATE lm_size_t
_LM_GetProcessBitsEx(lm_pid_t pid)
{
	BOOL IsWow64;
	lm_size_t sysbits;
	HANDLE hProcess;
	lm_size_t bits = LM_BITS;

	if (!_LM_OpenProc(pid, &hProcess))
		return bits;

	if (!IsWow64Process(hProcess, &IsWow64))
		goto CLOSE_EXIT;

	sysbits = LM_GetSystemBits();

	if (sysbits == 32 || IsWow64)
		bits = 32;
	else if (sysbits == 64)
		bits = 64;

CLOSE_EXIT:
	_LM_CloseProc(&hProcess);

	return bits;
}
