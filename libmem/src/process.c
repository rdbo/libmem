#include "internal.h"

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumProcessIds(lm_bool_t(*callback)(lm_pid_t   pid,
					lm_void_t *arg),
		   lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	PROCESSENTRY32 entry;
		
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return ret;

	entry.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hSnap, &entry)) {
		do {
			lm_pid_t pid = (lm_pid_t)(
				entry.th32ProcessID
			);

			if (callback(pid, arg) == LM_FALSE)
				break;
		} while (Process32Next(hSnap, &entry));

		ret = LM_TRUE;
	}

	CloseHandle(hSnap);
	
	return ret;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_bool_t
_LM_EnumProcessIds(lm_bool_t(*callback)(lm_pid_t   pid,
					lm_void_t *arg),
		   lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	struct procstat *ps;
	unsigned int nprocs = 0;
	struct kinfo_proc *procs;

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
			lm_pid_t pid = (lm_pid_t)(
				procs[i].ki_pid
			);

			if (callback(pid, arg) == LM_FALSE)
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
_LM_EnumProcessIds(lm_bool_t(*callback)(lm_pid_t   pid,
					lm_void_t *arg),
		   lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	struct dirent *pdirent;
	DIR *dir;

	dir = opendir(LM_PROCFS);

	if (!dir)
		return ret;
		
	while ((pdirent = readdir(dir))) {
		lm_pid_t pid = (lm_pid_t)LM_ATOI(pdirent->d_name);

		if (pid || (!pid && !LM_STRCMP(pdirent->d_name,
					       LM_STR("0")))) {
			if (callback(pid, arg) == LM_FALSE)
				break;
		}
	}

	ret = LM_TRUE;
		
	closedir(dir);
	return ret;
}
#endif

LM_API lm_bool_t
LM_EnumProcessIds(lm_bool_t(*callback)(lm_pid_t   pid,
				       lm_void_t *arg),
		  lm_void_t *arg)
{
	LM_ASSERT(callback != LM_NULLPTR);

	return _LM_EnumProcessIds(callback, arg);
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

LM_API lm_pid_t
LM_GetProcessId(lm_void_t)
{
	return _LM_GetProcessId();
}

/********************************/

typedef struct {
	lm_pid_t     pid;
	lm_tstring_t procstr;
	lm_size_t    len;
} _lm_find_pid_t;

LM_PRIVATE lm_bool_t
_LM_FindProcessIdCallback(lm_pid_t   pid,
			  lm_void_t *arg)
{
	lm_bool_t	  ret = LM_TRUE;
	lm_process_t	  proc;
	_lm_find_pid_t *parg = (_lm_find_pid_t *)arg;
	lm_tchar_t	 *path;

	path = (lm_tchar_t *)LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!path)
		return LM_FALSE;

	if (LM_OpenProcessEx(pid, &proc)) {
		lm_size_t len;

		len = LM_GetProcessPathEx(proc,	path, LM_PATH_MAX);
		if (len && len >= parg->len) {
			path[len] = LM_STR('\x00');

			if (!LM_STRCMP(&path[len - parg->len], 
				       parg->procstr)) {
				parg->pid = pid;
				ret = LM_FALSE;
			}
		}

		LM_CloseProcess(&proc);
	}

	LM_FREE(path);

	return ret;
}

LM_API lm_pid_t
LM_FindProcessId(lm_tstring_t procstr)
{
	_lm_find_pid_t arg;

	LM_ASSERT(procstr != LM_NULLPTR);

	arg.pid = LM_PID_BAD;
	arg.procstr = procstr;
	arg.len = LM_STRLEN(arg.procstr);

	LM_EnumProcessIds(_LM_FindProcessIdCallback, (lm_void_t *)&arg);
	return arg.pid;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t)
{
	return LM_GetParentIdEx(LM_GetProcessId());
}
#else
LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t)
{
	return (lm_pid_t)getppid();
}
#endif

LM_API lm_pid_t
LM_GetParentId(lm_void_t)
{
	return _LM_GetParentId();
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
LM_GetParentIdEx(lm_pid_t pid)
{
	LM_ASSERT(pid != LM_PID_BAD);

	return _LM_GetParentIdEx(pid);
}

/********************************/

typedef struct {
	lm_pid_t  pid;
	lm_bool_t is_alive;
} _lm_is_proc_alive_t;

LM_PRIVATE lm_bool_t
_LM_IsProcessAliveCallback(lm_pid_t   pid,
			   lm_void_t *arg)
{
	_lm_is_proc_alive_t *parg = (_lm_is_proc_alive_t *)arg;

	if (parg->pid == pid) {
		parg->is_alive = LM_TRUE;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_bool_t
LM_IsProcessAlive(lm_pid_t pid)
{
	_lm_is_proc_alive_t arg;
	arg.pid      = pid;
	arg.is_alive = LM_FALSE;

	LM_EnumProcessIds(_LM_IsProcessAliveCallback, (lm_void_t *)&arg);

	return arg.is_alive;
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
	lm_size_t len = 0;
	lm_process_t proc;

	if (LM_OpenProcess(&proc)) {
		len = LM_GetProcessPathEx(proc, pathbuf, maxlen);
		LM_CloseProcess(&proc);
	}

	return len;
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

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_process_t proc,
		     lm_tchar_t  *pathbuf,
		     lm_size_t    maxlen)
{
	return (lm_size_t)GetModuleFileNameEx(proc.handle, NULL,
					      pathbuf, maxlen);
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_process_t proc,
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
		proc.pid, &nprocs
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
_LM_GetProcessPathEx(lm_process_t proc,
		     lm_tchar_t  *pathbuf,
		     lm_size_t    maxlen)
{
	ssize_t slen;
	lm_tchar_t exe_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
	LM_SNPRINTF(exe_path, LM_ARRLEN(exe_path),
		    LM_STR("%s/%d/exe"), LM_PROCFS, proc.pid);
	
	/* readlink does not append a null terminator, so use maxlen - 1
	   and append it later */
	slen = readlink(exe_path, pathbuf, maxlen - 1);
	if (slen == -1)
		slen = 0;
	return (lm_size_t)slen;
}
#endif

LM_API lm_size_t
LM_GetProcessPathEx(lm_process_t proc,
		    lm_tchar_t  *pathbuf,
		    lm_size_t    maxlen)
{
	lm_size_t len;

	LM_ASSERT(LM_VALID_PROCESS(proc) &&
		  pathbuf != LM_NULLPTR &&
		  maxlen > 0);

	len = _LM_GetProcessPathEx(proc, pathbuf, maxlen);

	pathbuf[len] = LM_STR('\x00');

	return len;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_GetProcessName(lm_tchar_t *namebuf,
		   lm_size_t   maxlen)
{
	/* According to the Windows API Docs, GetModuleBaseName
	   should not be called on the current process, instead
	   you should get the full path with GetModuleFileName
	   and find the last '\' character.

	   MS Docs (https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulebasenamea):
	   "To retrieve the base name of a module in the current
	   process, use the GetModuleFileName function to retrieve
	   the full module name and then use a function call such as
	   strrchr(szmodulename, '\') to scan to the beginning of the
	   base name within the module name string. This is more efficient
	   and more reliable than calling GetModuleBaseName with a handle
	   to the current process."
	 */

	lm_size_t len = 0;
	lm_tchar_t path[LM_PATH_MAX];
	lm_tchar_t *ptr;

	if (!LM_GetProcessPath(path, LM_PATH_MAX))
		return len;

	ptr = LM_STRRCHR(path, LM_STR('\\'));
	if (!ptr)
		return len;

	ptr = &ptr[1];
	len = LM_STRLEN(ptr);
	if (len >= maxlen)
		len = maxlen - 1;

	LM_STRNCPY(namebuf, ptr, len);
	namebuf[len] = LM_STR('\x00');

	return len;
}
#else
LM_PRIVATE lm_size_t
_LM_GetProcessName(lm_tchar_t *namebuf,
		   lm_size_t   maxlen)
{
	lm_size_t len = 0;
	lm_process_t proc;

	if (LM_OpenProcess(&proc)) {
		len = LM_GetProcessNameEx(proc, namebuf, maxlen);
		LM_CloseProcess(&proc);
	}

	return len;
}
#endif

LM_API lm_size_t
LM_GetProcessName(lm_tchar_t *namebuf,
		  lm_size_t   maxlen)
{
	LM_ASSERT(namebuf != LM_NULLPTR && maxlen > 0);

	return _LM_GetProcessName(namebuf, maxlen);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_GetProcessNameEx(lm_process_t proc,
		     lm_tchar_t  *namebuf,
		     lm_size_t    maxlen)
{
	len = (lm_size_t)GetModuleBaseName(proc.handle, NULL, namebuf, maxlen);
	return len;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_size_t
_LM_GetProcessNameEx(lm_process_t proc,
		     lm_tchar_t  *namebuf,
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
		proc.pid, &nprocs
	);

	if (procs && nprocs) {
		len = LM_STRLEN(procs->ki_comm);
		if (len >= maxlen)
			len = maxlen - 1;

		LM_STRNCPY(namebuf, procs->ki_comm, len);

		procstat_freeprocs(ps, procs);
	}

	procstat_close(ps);

	return len;
}
#else
LM_PRIVATE lm_size_t
_LM_GetProcessNameEx(lm_process_t proc,
		     lm_tchar_t  *namebuf,
		     lm_size_t    maxlen)
{
	lm_size_t   len = 0;
	size_t      buf_len;
	lm_tchar_t *comm_line = NULL;
	lm_tchar_t  comm_path[LM_PATH_MAX];
	FILE       *comm_file;

	LM_SNPRINTF(comm_path, LM_ARRLEN(comm_path),
		    LM_STR("%s/%d/comm"), LM_PROCFS, proc.pid);

	comm_file = LM_FOPEN(comm_path, "r");
	if (!comm_file)
		return len;

	if ((len = LM_GETLINE(&comm_line, &buf_len, comm_file)) <= 0)
		goto CLEAN_EXIT;

	--len; /* remove new line */
	if (len >= maxlen)
		len = maxlen - 1;

	LM_STRNCPY(namebuf, comm_line, len);
CLEAN_EXIT:
	LM_FREE(comm_line); /* the buffer should be freed even if getline fails (according to the getline man page) */
	LM_FCLOSE(comm_file);
	return len;
}
#endif

LM_API lm_size_t
LM_GetProcessNameEx(lm_process_t proc,
		    lm_tchar_t  *namebuf,
		    lm_size_t    maxlen)
{
	lm_size_t len;

	LM_ASSERT(LM_VALID_PROCESS(proc) &&
		  namebuf != LM_NULLPTR &&
		  maxlen > 0);

	len = _LM_GetProcessNameEx(proc, namebuf, maxlen);

	namebuf[len] = LM_STR('\x00');

	return len;
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

LM_API lm_size_t
LM_GetProcessBits(lm_void_t)
{
	return (lm_size_t)LM_BITS;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_void_t
_LM_GetProcessBitsEx(lm_process_t proc,
		     lm_size_t   *bits)
{
	BOOL IsWow64;
	lm_size_t sysbits;

	if (!IsWow64Process(proc.handle, &IsWow64))
		return;

	sysbits = LM_GetSystemBits();

	if (sysbits == 32 || IsWow64)
		*bits = 32;
	else if (sysbits == 64)
		*bits = 64;
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

LM_PRIVATE lm_void_t
_LM_GetProcessBitsEx(lm_process_t proc,
		     lm_size_t   *bits)
{
	lm_tchar_t path[LM_PATH_MAX];
	lm_size_t elf_bits;

	if (!LM_GetProcessPathEx(proc, path, LM_PATH_MAX))
		return;

	elf_bits = _LM_GetElfBits(path);
	if (elf_bits)
		*bits = elf_bits;
}
#endif

LM_API lm_size_t
LM_GetProcessBitsEx(lm_process_t proc)
{
	lm_size_t bits = LM_BITS;

	LM_ASSERT(LM_VALID_PROCESS(proc));

	_LM_GetProcessBitsEx(proc, &bits);

	return bits;
}

