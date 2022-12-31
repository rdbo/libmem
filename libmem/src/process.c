#include "internal.h"

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_GetProcessBitsEx(lm_process_t *pproc)
{
	HANDLE hProcess;
	BOOL IsWow64;
	lm_size_t sysbits;
	lm_size_t bits = 0;

	if (!_LM_OpenProcess(pproc->pid, &hProcess))
		return;

	if (IsWow64Process(hProcess, &IsWow64)) {
		sysbits = LM_GetSystemBits();

		if (sysbits == 32 || IsWow64)
			bits = 32;
		else if (sysbits == 64)
			bits = 64;
	}

	_LM_CloseProcess(&hProcess);

	if (!bits)
		bits = LM_BITS;

	return bits;
}
#else
LM_PRIVATE lm_size_t
_LM_GetElfBits(lm_tchar_t *path)
{
	lm_size_t bits = 0;
	int fd;
	unsigned char elf_num;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return bits;

	/*
	 * ELF Magic:
	 * 32 bits -> 0x7F, E, L, F, 1
	 * 64 bits -> 0x7F, E, L, F, 2
	 */

	lseek(fd, EI_MAG3 + 1, SEEK_SET);
	if (read(fd, &elf_num, sizeof(elf_num)) > 0 &&
	    (elf_num == 1 || elf_num == 2))
		bits = elf_num * 32;

	close(fd);

	return bits;
}

LM_PRIVATE lm_size_t
_LM_GetProcessBitsEx(lm_process_t *pproc)
{
	lm_size_t elf_bits;

	elf_bits = _LM_GetElfBits(pproc->path);
	if (!elf_bits)
		elf_bits = LM_BITS;

	return elf_bits;
}

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t     pid,
		     lm_tchar_t  *pathbuf,
		     lm_size_t    maxlen)
{
	HANDLE    hProcess;
	lm_size_t len = 0;

	if (!_LM_OpenProcess(pid, &hProcess))
		return len;

	len = (lm_size_t)GetModuleFileNameEx(hProcess, NULL, pathbuf, maxlen);

	_LM_CloseProcess(&hProcess);

	/* From: https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexa
	 * "A pointer to a buffer that receives the fully qualified
	 * path to the module. If the size of the file name is larger
	 * than the value of the nSize parameter, the function succeeds
	 * but the file name is truncated and null-terminated."
	 *
	 * It doesn't mention whether it's null-terminater or not when
	 * the file name is not truncated, so it will be forcefully appended
	 */

	if (len >= maxlen)
		len = maxlen - 1;
	pathbuf[len] = LM_STR('\x00');

	return len;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t     pid,
		     lm_tchar_t  *pathbuf,
		     lm_size_t    maxlen)
{
	lm_size_t len = 0;
	struct procstat *ps;
	unsigned int nprocs = 0;
	struct kinfo_proc *procs;

	ps = procstat_open_sysctl();
	if (!ps)
		return len;

	procs = procstat_getprocs(
		ps, KERN_PROC_PID,
		pid, &nprocs
	);

	if (procs && nprocs) {
		if (!procstat_getpathname(ps, procs,
					  pathbuf, maxlen))
			len = LM_STRLEN(pathbuf);

		procstat_freeprocs(ps, procs);
	}

	procstat_close(ps);

	return len;
}
#else
LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t     pid,
		     lm_tchar_t  *pathbuf,
		     lm_size_t    maxlen)
{
	ssize_t slen;
	lm_tchar_t exe_path[LM_PATH_MAX] = { 0 };
	LM_SNPRINTF(exe_path, LM_ARRLEN(exe_path),
		    LM_STR("%s/%d/exe"), LM_PROCFS, pid);
	
	/* readlink does not append a null terminator, so use maxlen - 1
	   and append it later */
	slen = readlink(exe_path, pathbuf, maxlen - 1);
	if (slen == -1)
		slen = 0;

	pathbuf[slen] = LM_STR('\x00');

	return (lm_size_t)slen;
}
#endif


/********************************/

LM_PRIVATE lm_tchar_t *
_LM_GetNameFromPath(lm_tchar_t *path)
{
	lm_tchar_t *holder;

	LM_ASSERT(path != LM_NULLPTR);

	holder = LM_STRRCHR(path, LM_PATH_SEP);
	holder = &holder[1]; /* don't include the path separator */

	return holder;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_GetProcessPath(lm_tchar_t *pathbuf,
		   lm_size_t   maxlen)
{
	HMODULE hModule = GetModuleHandle(NULL);
	if (!hModule)
		return len;

	return (lm_size_t)GetModuleFileName(hModule, pathbuf, maxlen);
}
#else
LM_PRIVATE lm_size_t
_LM_GetProcessPath(lm_tchar_t *pathbuf,
		   lm_size_t   maxlen)
{
	lm_process_t proc;
	if (LM_GetProcess(&proc))
		return 0;

	return _LM_GetProcessPathEx(&proc, pathbuf, maxlen);
}
#endif

LM_API lm_size_t
LM_GetProcessPath(lm_tchar_t *pathbuf,
		  lm_size_t   maxlen)
{
	lm_size_t len;

	LM_ASSERT(pathbuf != LM_NULLPTR && maxlen > 0);

	len = _LM_GetProcessPath(pathbuf, maxlen);
	pathbuf[len] = LM_STR('\x00');
	return len;
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_FillProcess(lm_pid_t      pid,
		lm_process_t *pproc)
{
	if (pid == LM_PID_BAD)
		return LM_FALSE;

	pproc->pid = pid;
	if (!_LM_GetProcessPathEx(pproc->pid, pproc->path, LM_ARRLEN(pproc->path)))
		return LM_FALSE;

	if (!(pproc->name = _LM_GetNameFromPath(pproc->path)))
		return LM_FALSE;

	pproc->bits = _LM_GetProcessBitsEx(pproc);
	return LM_TRUE;
}

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumProcesses(lm_bool_t(*callback)(lm_process_t *pproc,
					lm_void_t   *arg),
		   lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	PROCESSENTRY32 entry;
	lm_pid_t     pid;
	lm_process_t proc;

	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return ret;

	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &entry)) {
		do {
			
			pid = (lm_pid_t)entry.th32ProcessID;

			if (!_LM_FillProcess(pid, &proc))
				continue;

			if (callback(&proc, arg) == LM_FALSE)
				break;
		} while (Process32Next(hSnap, &entry));

		ret = LM_TRUE;
	}

	CloseHandle(hSnap);

	return ret;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_bool_t
_LM_EnumProcesses(lm_bool_t(*callback)(lm_process_t *pproc,
				       lm_void_t    *arg),
		  lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	struct procstat *ps;
	unsigned int nprocs = 0;
	struct kinfo_proc *procs;
	lm_pid_t     pid;
	lm_process_t proc;

	ps = procstat_open_sysctl();
	if (!ps)
		return ret;
		
	procs = procstat_getprocs(
		ps, KERN_PROC_PROC, 
		0, &nprocs
	);

	if (procs) {
		unsigned int i;

		for (i = 0; i < nprocs; ++i) {
			pid = (lm_pid_t)procs[i].ki_pid;
			if (!_LM_FillProcess(pid, &proc))
				continue;

			if (callback(&proc, arg) == LM_FALSE)
				break;
		}

		procstat_freeprocs(ps, procs);

		ret = LM_TRUE;
	}

	procstat_close(ps);

	return ret;
}
#else
LM_PRIVATE lm_bool_t
_LM_EnumProcessIds(lm_bool_t(*callback)(lm_process_t *pproc,
					lm_void_t    *arg),
		   lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	struct dirent *pdirent;
	DIR *dir;
	lm_pid_t     pid;
	lm_process_t proc;

	dir = opendir(LM_PROCFS);

	if (!dir)
		return ret;
		
	while ((pdirent = readdir(dir))) {
		pid = (lm_pid_t)LM_ATOI(pdirent->d_name);

		if (!pid && LM_STRCMP(pdirent->d_name, LM_STR("0")))
			continue;

		if (!_LM_FillProcess(pid, &proc))
			continue;

		if (callback(&proc, arg) == LM_FALSE)
			break;
	}

	ret = LM_TRUE;
		
	closedir(dir);
	return ret;
}
#endif

LM_API lm_bool_t
LM_EnumProcesses(lm_bool_t(*callback)(lm_process_t *pproc,
				      lm_void_t    *arg),
		  lm_void_t *arg)
{
	LM_ASSERT(callback != LM_NULLPTR);

	return _LM_EnumProcesses(callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_pid_t
_LM_GetProcessId(lm_void_t)
{
	return (lm_pid_t)GetCurrentProcessId();
}
#else
LM_PRIVATE lm_pid_t
_LM_GetProcessId(lm_void_t)
{
	return (lm_pid_t)getpid();
}
#endif

LM_API lm_bool_t
LM_GetProcess(lm_process_t *procbuf)
{
	/*
	 * There's no need to do all these operations everytime
	 * this function is called. Just store the results in
	 * a static variable, since they'll never change anyways
	 */
	static lm_process_t proc = { LM_PID_BAD, 0, { 0 }, LM_NULLPTR };
	if (proc.pid == LM_PID_BAD) {
		proc.pid = _LM_GetProcessId();
		if (!_LM_GetProcessPath(proc.path, LM_ARRLEN(proc.path)))
			return LM_FALSE;

		if (!(procbuf->name = _LM_GetNameFromPath(procbuf->path)))
			return LM_FALSE;

		procbuf->bits = LM_BITS;
	}

	*procbuf = proc;

	return LM_TRUE;
}

/********************************/

typedef struct {
	lm_process_t *pproc;
	lm_tstring_t  procstr;
	lm_size_t     len;
} _lm_find_pid_t;

LM_PRIVATE lm_bool_t
_LM_FindProcessCallback(lm_process_t *pproc,
			lm_void_t    *arg)
{
	lm_bool_t	  ret = LM_TRUE;
	_lm_find_pid_t   *parg = (_lm_find_pid_t *)arg;
	lm_size_t         len;

	len = LM_STRLEN(pproc->path);
	if (len >= parg->len) {
		if (!LM_STRCMP(&pproc->path[len - parg->len], parg->procstr)) {
			*(parg->pproc) = *pproc;
			ret = LM_FALSE;
		}
	}

	return ret;
}

LM_API lm_bool_t
LM_FindProcess(lm_tstring_t  name,
	       lm_process_t *procbuf)
{
	_lm_find_pid_t arg;

	LM_ASSERT(name != LM_NULLPTR && procbuf != LM_NULLPTR);

	arg.pproc = procbuf;
	arg.pproc->pid = LM_PID_BAD;
	arg.procstr = name;
	arg.len = LM_STRLEN(arg.procstr);

	LM_ASSERT(arg.len > 0);

	LM_EnumProcesses(_LM_FindProcessCallback, (lm_void_t *)&arg);
	return arg.pproc->pid != LM_PID_BAD ? LM_TRUE : LM_FALSE;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t)
{
	return _LM_GetParentIdEx(LM_GetProcess());
}
#else
LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t)
{
	return (lm_pid_t)getppid();
}
#endif

LM_API lm_bool_t
LM_GetParentProcess(lm_process_t *pproc)
{
	lm_pid_t ppid = _LM_GetParentId();
	return _LM_FillProcess(ppid, pproc);
}

/********************************/

#if LM_OS == LM_OS_WIN
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
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_pid_t
_LM_GetParentIdEx(lm_pid_t pid)
{
	lm_pid_t ppid = LM_PID_BAD;
	struct procstat *ps;
	unsigned int nprocs = 0;
	struct kinfo_proc *procs;

	ps = procstat_open_sysctl();
	if (!ps)
		return ppid;

	procs = procstat_getprocs(
		ps, KERN_PROC_PID,
		pid, &nprocs
	);

	if (procs && nprocs) {
		ppid = (lm_pid_t)procs[0].ki_ppid;
		procstat_freeprocs(ps, procs);
	}

	procstat_close(ps);

	return ppid;
}
#else
LM_PRIVATE lm_pid_t
_LM_GetParentIdEx(lm_pid_t pid)
{
	lm_pid_t    ppid = LM_PID_BAD;	
	lm_tchar_t  status_path[LM_PATH_MAX] = { 0 };
	FILE       *status_file;
	lm_tchar_t *status_line = NULL;
	regex_t     regex;
	size_t      buf_len;
	regmatch_t  matches[2];

	LM_SNPRINTF(status_path, LM_ARRLEN(status_path),
		    LM_STR("%s/%d/status"), LM_PROCFS, pid);

	status_file = LM_FOPEN(status_path, "r");
	if (!status_file)
		return ppid;

	if (regcomp(&regex, "^PPid:[[:blank:]]+([0-9]+).*$", REG_EXTENDED))
		goto CLOSE_EXIT;

	while (LM_GETLINE(&status_line, &buf_len, status_file) > 0) {
		if (regexec(&regex, status_line, LM_ARRLEN(matches), matches, 0))
			continue;

		status_line[matches[1].rm_eo] = '\x00';
		ppid = LM_ATOI(&status_line[matches[1].rm_so]);
		break;
	}

	regfree(&regex);
	LM_FREE(status_line);
CLOSE_EXIT:
	LM_FCLOSE(status_file);

	return ppid;
}
#endif

LM_API lm_pid_t
LM_GetParentProcessEx(lm_process_t *pproc,
		      lm_process_t *procbuf)
{
	lm_pid_t pid;
	LM_ASSERT(pproc != LM_NULLPTR && procbuf != LM_NULLPTR);

	pid = _LM_GetParentIdEx(pid);
	return _LM_FillProcess(pid, procbuf);
}

/********************************/

typedef struct {
	lm_process_t *pproc;
	lm_bool_t     is_alive;
} _lm_is_proc_alive_t;

LM_PRIVATE lm_bool_t
_LM_IsProcessAliveCallback(lm_process_t *pproc,
			   lm_void_t    *arg)
{
	_lm_is_proc_alive_t *parg = (_lm_is_proc_alive_t *)arg;

	if (parg->pproc->pid == pproc->pid) {
		parg->is_alive = LM_TRUE;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_bool_t
LM_IsProcessAlive(lm_process_t *pproc)
{
	_lm_is_proc_alive_t arg;
	arg.pproc    = pproc;
	arg.is_alive = LM_FALSE;

	LM_EnumProcesses(_LM_IsProcessAliveCallback, (lm_void_t *)&arg);

	return arg.is_alive;
}

/********************************/

#if LM_OS == LM_OS_WIN
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
#else
LM_PRIVATE lm_void_t
_LM_GetSystemBits(lm_size_t *bits)
{
	struct utsname utsbuf;

	if (uname(&utsbuf))
		return;
		
	if (!LM_STRCMP(utsbuf.machine, LM_STR("x86_64")) ||
	    !LM_STRCMP(utsbuf.machine, LM_STR("amd64")) ||
	    !LM_STRCMP(utsbuf.machine, LM_STR("aarch64")))
		*bits = 64;
}
#endif

LM_API lm_size_t
LM_GetSystemBits(lm_void_t)
{
	lm_size_t bits = LM_BITS;

	_LM_GetSystemBits(&bits);

	return bits;
}

/********************************/

#endif

