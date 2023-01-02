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

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumProcesses(lm_bool_t(*callback)(lm_process_t *pproc,
				       lm_void_t    *arg),
		   lm_void_t *arg)
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
			proc.ppid = (lm_pid_t)entry.th32ParentProcessID;
			/* OBS: The 'szExeFile' member of the 'PROCESSENTRY32'
			 * struct represents the name of the process, not the
			 * full path of the executable.
			 * Source: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32 */
			if (!_LM_GetProcessPathEx(proc.pid, proc.path, LM_ARRLEN(proc.path)))
				continue;

			len = LM_STRLEN(entry.szExeFile);
			if (len >= LM_ARRLEN(proc.name))
				len = LM_ARRLEN(proc.name) - 1;

			LM_STRNCPY(proc.name, entry.szExeFile, len);
			proc.bits = _LM_GetProcessBitsEx(proc.pid);

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
	lm_process_t proc;
	lm_size_t    len;

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
			proc.pid = (lm_pid_t)procs[i].ki_pid;
			proc.ppid = (lm_pid_t)procs[i].ki_ppid;
			if (!_LM_GetProcessPathEx(proc.pid, proc.path, LM_ARRLEN(proc.path)))
				continue;

			len = LM_STRLEN(procs[i].ki_comm);
			if (len >= LM_ARRLEN(proc.name))
				len = LM_ARRLEN(proc.name) - 1;

			LM_STRNCPY(proc.name, procs[i].ki_comm, len);

			proc.bits = LM_BITS;
			proc.bits = _LM_GetProcessBitsEx(proc.path);

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
_LM_EnumProcesses(lm_bool_t(*callback)(lm_process_t *pproc,
				       lm_void_t    *arg),
		  lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	struct dirent *pdirent;
	DIR *dir;
	lm_process_t proc;

	dir = opendir(LM_PROCFS);

	if (!dir)
		return ret;
		
	while ((pdirent = readdir(dir))) {
		proc.pid = (lm_pid_t)LM_ATOI(pdirent->d_name);

		/* check if 'atoi' failed */
		if (!proc.pid && LM_STRCMP(pdirent->d_name, LM_STR("0")))
			continue;

		proc.ppid = _LM_GetParentIdEx(proc.pid);
		if (!_LM_GetProcessPathEx(proc.pid, proc.path, LM_ARRLEN(proc.path)))
			continue;

		if (!_LM_GetProcessNameEx(proc.pid, proc.name, LM_ARRLEN(proc.name)))
			continue;

		proc.bits = LM_BITS;
		proc.bits = _LM_GetProcessBitsEx(proc.path);

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

LM_PRIVATE lm_bool_t
_LM_GetProcess(lm_process_t *procbuf)
{
	procbuf->pid = _LM_GetProcessId();
	procbuf->ppid = _LM_GetParentId();

	if (!_LM_GetProcessPath(procbuf->path, LM_ARRLEN(procbuf->path)))
		return LM_FALSE;

	if (!_LM_GetProcessName(procbuf->name, LM_ARRLEN(procbuf->name)))
		return LM_FALSE;

	procbuf->bits = LM_BITS;
	return LM_TRUE;
}

LM_API lm_bool_t
LM_GetProcess(lm_process_t *procbuf)
{
	static lm_process_t self_proc = {
		LM_PID_BAD, LM_PID_BAD, 0, "", ""
	};

	LM_ASSERT(procbuf != LM_NULLPTR);

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

typedef struct {
	lm_process_t *procbuf;
	lm_tstring_t  procstr;
	lm_size_t     len;
} _lm_find_pid_t;

LM_PRIVATE lm_bool_t
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

LM_API lm_bool_t
LM_FindProcess(lm_tstring_t  procstr,
	       lm_process_t *procbuf)
{
	_lm_find_pid_t arg;

	LM_ASSERT(procstr != LM_NULLPTR);

	arg.procbuf = procbuf;
	arg.procbuf->pid = LM_PID_BAD;
	arg.procstr = procstr;
	arg.len = LM_STRLEN(arg.procstr);

	LM_EnumProcesses(_LM_FindProcessCallback, (lm_void_t *)&arg);

	return arg.procbuf->pid != LM_PID_BAD ? LM_TRUE : LM_FALSE;
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

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t)
{
	return _LM_GetParentIdEx(_LM_GetProcessId());
}
#else
LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t)
{
	return (lm_pid_t)getppid();
}
#endif

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
	lm_tchar_t  stat_path[LM_PATH_MAX] = { 0 };
	FILE       *stat_file;
	lm_tchar_t *stat_line = NULL;
	size_t      buf_len;

	LM_SNPRINTF(stat_path, LM_ARRLEN(stat_path),
		    LM_STR("%s/%d/stat"), LM_PROCFS, pid);

	stat_file = LM_FOPEN(stat_path, "r");
	if (!stat_file)
		return ppid;

	if (LM_GETLINE(&stat_line, &buf_len, stat_file) > 0)
		LM_SSCANF(stat_line, "%*d %*s %*c %d", &ppid);

	LM_FREE(stat_line);
CLOSE_EXIT:
	LM_FCLOSE(stat_file);

	return ppid;
}
#endif

/********************************/

#if LM_OS == LM_OS_WIN
LM_API lm_bool_t
_LM_IsProcessAlive(lm_process_t *pproc)
{
	HANDLE hProcess;

	/* _LM_OpenProc already checks if the process
	 * has terminated by looking if it has an
	 * exit code. */
	if (!_LM_OpenProc(pproc->pid, &hProcess))
		return LM_FALSE;

	_LM_CloseProc(&hProcess);

	return LM_TRUE;
}
#else
LM_API lm_bool_t
_LM_IsProcessAlive(lm_process_t *pproc)
{
	lm_tchar_t proc_path[LM_PATH_MAX];
	DIR *pdir;

	LM_SNPRINTF(proc_path, sizeof(proc_path),
		    "%s/%d", LM_PROCFS, pproc->pid);

	if (!(pdir = opendir(proc_path)))
		return LM_FALSE;

	closedir(pdir);

	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_IsProcessAlive(lm_process_t *pproc)
{
	return _LM_IsProcessAlive(pproc);
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
	return _LM_GetProcessPathEx(_LM_GetProcessId(), pathbuf, maxlen);
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
_LM_GetProcessPathEx(lm_pid_t      pid,
		     lm_tchar_t   *pathbuf,
		     lm_size_t     maxlen)
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
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t      pid,
		     lm_tchar_t   *pathbuf,
		     lm_size_t     maxlen)
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
_LM_GetProcessPathEx(lm_pid_t      pid,
		     lm_tchar_t   *pathbuf,
		     lm_size_t     maxlen)
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
	return _LM_GetProcessNameEx(_LM_GetProcessId(), namebuf, maxlen);
}
#endif

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_GetProcessNameEx(lm_pid_t    pid,
		     lm_tchar_t *namebuf,
		     lm_size_t   maxlen)
{
	lm_size_t len = 0;
	HANDLE hProcess;

	if (!_LM_OpenProc(pid, &hProcess))
		return len;

	len = (lm_size_t)GetModuleBaseName(hProcess, NULL, namebuf, maxlen);

	_LM_CloseProcess(&hProcess);

	namebuf[len] = LM_STR('\x00');

	return len;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_size_t
_LM_GetProcessNameEx(lm_pid_t    pid,
		     lm_tchar_t *namebuf,
		     lm_size_t   maxlen)
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
		len = LM_STRLEN(procs->ki_comm);
		if (len >= maxlen)
			len = maxlen - 1;

		LM_STRNCPY(namebuf, procs->ki_comm, len);
		namebuf[len] = LM_STR('\x00');
		procstat_freeprocs(ps, procs);
	}

	procstat_close(ps);

	return len;
}
#else
LM_PRIVATE lm_size_t
_LM_GetProcessNameEx(lm_pid_t    pid,
		     lm_tchar_t *namebuf,
		     lm_size_t   maxlen)
{
	lm_size_t   len = 0;
	size_t      buf_len;
	lm_tchar_t *comm_line = NULL;
	lm_tchar_t  comm_path[LM_PATH_MAX];
	FILE       *comm_file;

	LM_SNPRINTF(comm_path, LM_ARRLEN(comm_path),
		    LM_STR("%s/%d/comm"), LM_PROCFS, pid);

	comm_file = LM_FOPEN(comm_path, "r");
	if (!comm_file)
		return len;

	if ((len = LM_GETLINE(&comm_line, &buf_len, comm_file)) <= 0)
		goto CLEAN_EXIT;

	--len; /* remove new line */
	if (len >= maxlen)
		len = maxlen - 1;

	LM_STRNCPY(namebuf, comm_line, len);
	namebuf[len] = LM_STR('\x00');
CLEAN_EXIT:
	LM_FREE(comm_line); /* the buffer should be freed even if getline fails (according to the getline man page) */
	LM_FCLOSE(comm_file);
	return len;
}
#endif

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

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_GetProcessBitsEx(lm_pid_t pid)
{
	BOOL IsWow64;
	lm_size_t sysbits;
	HANDLE hProcess;
	lm_size_t bits = LM_BITS;

	if (!_LM_OpenProc(pid, &hProcess))
		return;

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
_LM_GetProcessBitsEx(lm_tchar_t *elfpath)
{
	lm_size_t elf_bits;

	elf_bits = _LM_GetElfBits(elfpath);
	if (!elf_bits)
		elf_bits = LM_BITS;

	return elf_bits;
}
#endif

