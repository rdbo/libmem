/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

#include "libmem.h"

#if LM_COMPATIBLE
/* Additional Types */
typedef struct {
	lm_pid_t     pid;
	lm_tstring_t procstr;
	lm_size_t    len;
} _lm_get_pid_t;

/* Helpers */
static lm_bool_t
_LM_CheckProcess(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

	if (proc.pid == (lm_pid_t)LM_BAD)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (proc.pid != LM_GetProcessId() && !proc.handle)
			return ret;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		
	}
#	endif

	ret = LM_TRUE;

	return ret;
}

#if LM_OS == LM_OS_WIN
#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
static lm_size_t
_LM_OpenFileBuf(lm_tstring_t path, 
		lm_tchar_t **pfilebuf)
{
	int         fd;
	lm_size_t   total = 0;
	lm_tchar_t  buf[1024];
	ssize_t     rdsize;
	lm_tchar_t *filebuf = (lm_tchar_t *)LM_NULL;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return total;
	
	while ((rdsize = read(fd, buf, sizeof(buf)) > 0)) {
		lm_tchar_t *old_filebuf;

		rdsize /= sizeof(buf[0]);

		filebuf = LM_CALLOC(total + (size_t)rdsize + 1,
				    sizeof(lm_tchar_t));
		old_filebuf = filebuf;

		if (old_filebuf) {
			if (filebuf)
				LM_STRNCPY(filebuf, old_filebuf, total);

			LM_FREE(old_filebuf);
		}

		if (!filebuf) {
			total = 0;
			break;
		}

		LM_STRNCPY(&filebuf[total], buf, LM_ARRLEN(buf));
		total += (size_t)rdsize;
		filebuf[total] = '\x00';
	}

	if (filebuf)
		*pfilebuf = filebuf;

	close(fd);
	return total;
}

static lm_void_t
_LM_CloseFileBuf(lm_tchar_t **pfilebuf)
{
	if (pfilebuf && *pfilebuf) {
		LM_FREE(*pfilebuf);
		*pfilebuf = (lm_tchar_t *)LM_NULL;
	}
}
#endif

/* libmem */
LM_API lm_bool_t
LM_EnumProcesses(lm_bool_t(*callback)(lm_pid_t   pid,
				      lm_void_t *arg),
		 lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		HANDLE hSnap;
		
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 entry;

			entry.dwSize = sizeof(PROCESSENTRY32);
			if (Process32First(hSnap, &entry)) {
				do {
					lm_pid_t pid = (lm_pid_t)(
						entry.th32ProcessID;
					);

					if (callback(pid, arg) == LM_FALSE)
						break;
				} while (Process32Next(hSnap, &entry));

				ret = LM_TRUE;
			}
		}

		CloseHandle(hSnap);
	}
#	elif LM_OS == LM_OS_LINUX
	{
		struct dirent *pdirent;
		DIR *dir;

		dir = opendir(LM_STR(LM_PROCFS));

		if (!dir)
			return ret;
		
		while ((pdirent = readdir(dir))) {
			lm_pid_t pid = LM_ATOI(pdirent->d_name);

			if (pid || (!pid && !LM_STRCMP(pdirent->d_name, "0"))) {
				if (callback(pid, arg) == LM_FALSE)
					break;
			}
		}
		
		closedir(dir);
	}
#	elif LM_OS == LM_OS_BSD
	{
		struct procstat *ps;
		
		ps = procstat_open_sysctl();
		if (ps) {
			unsigned int nprocs = 0;
			struct kinfo_proc *procs = procstat_getprocs(
				ps, KERN_PROC_PROC, 
				pid, &nprocs
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
		}
	}
#	endif
	return ret;
}

static lm_bool_t
_LM_GetProcessIdCallback(lm_pid_t   pid,
			 lm_void_t *arg)
{
	lm_bool_t      ret = LM_TRUE;
	lm_process_t   proc;
	_lm_get_pid_t *parg = (_lm_get_pid_t *)arg;
	lm_tchar_t    *path;

	if (!parg)
		return LM_FALSE;

	path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));

	if (!path)
		return LM_FALSE;

	if (LM_OpenProcessEx(pid, &proc)) {
		lm_size_t len;

		len = LM_GetProcessPathEx(proc,	path, LM_PATH_MAX - 1);
		if (len && len >= parg->len) {
			path[len] = '\x00';

			if (!LM_STRCMP(&path[len - parg->len], 
				       parg->procstr)) {
				parg->pid = pid;
				ret = LM_FALSE;
			}
		}

		LM_CloseProcess(&proc);
	}

	return ret;
}

LM_API lm_pid_t
LM_GetProcessId(lm_void_t)
{
	lm_pid_t pid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		pid = GetCurrentProcessID();
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		pid = getpid();
	}
#	endif

	return pid;
}

LM_API lm_pid_t
LM_GetProcessIdEx(lm_tstring_t procstr)
{
	_lm_get_pid_t arg;

	arg.pid = (lm_pid_t)LM_BAD;
	arg.procstr = procstr;
	arg.len = LM_STRLEN(arg.procstr);

	LM_EnumProcesses(_LM_GetProcessIdCallback, (lm_void_t *)&arg);
	return arg.pid;
}

LM_API lm_pid_t
LM_GetParentId(lm_void_t)
{
	lm_pid_t ppid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		ppid = LM_GetParentIdEx(LM_GetProcessId());
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		ppid = getppid();
	}
#	endif

	if (!ppid)
		ppid = (lm_pid_t)LM_BAD;

	return ppid;
}

LM_API lm_pid_t
LM_GetParentIdEx(lm_pid_t pid)
{
	lm_pid_t ppid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		HANDLE hSnap;
		
		hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 entry;

			entry.dwSize = sizeof(PROCESSENTRY32);
			if (Process32First(hSnap, &entry)) {
				do {
					lm_pid_t curpid = (lm_pid_t)(
						entry.th32ProcessID;
					);

					if (curpid == pid) {
						ppid = (lm_pid_t)(
						      entry.th32ParentProcessID
						);

						break;
					}
				} while (Process32Next(hSnap, &entry));
			}
		}

		CloseHandle(hSnap);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *status_buf;
		lm_tchar_t  status_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
		lm_tchar_t *ptr;

		LM_SNPRINTF(status_path, LM_ARRLEN(status_path) - 1,
			    "%s/%d/status", LM_PROCFS, pid);
		
		if (!_LM_OpenFileBuf(status_path, &status_buf))
			return ppid;

		ptr = LM_STRSTR(status_buf, "\nPPid:\t");

		if (ptr) {
			ptr = LM_STRCHR(ptr, '\t');
			ptr = &ptr[1];
			ppid = (lm_pid_t)LM_ATOI(ptr);
		}

		_LM_CloseFileBuf(&status_buf);
	}
#	endif

	return ppid;
}

LM_API lm_bool_t
LM_OpenProcess(lm_process_t *procbuf)
{
	lm_bool_t ret = LM_FALSE;

	if (!procbuf)
		return ret;

	procbuf->pid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		procbuf->handle = GetCurrentProcess();
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		
	}
#	endif

	procbuf->pid = LM_GetProcessId();
	ret = LM_TRUE;

	return ret;
}

LM_API lm_bool_t
LM_OpenProcessEx(lm_pid_t      pid,
		 lm_process_t *procbuf)
{
	lm_bool_t ret = LM_FALSE;

	if (!procbuf)
		return ret;
	
	procbuf->pid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		if (pid != LM_GetProcessId()) {
			procbuf->handle = OpenProcess(LM_PROCESS_ACCESS,
					      FALSE,
					      pid);
		
			if (!procbuf->handle)
				return ret;
		} else {
			procbuf->handle = GetCurrentProcess();
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		
	}
#	endif

	procbuf->pid = pid;
	ret = LM_TRUE;

	return ret;
}

LM_API lm_void_t
LM_CloseProcess(lm_process_t *proc)
{
	if (!proc)
		return;
	
#	if LM_OS == LM_OS_WIN
	{
		if (proc->handle && proc->pid != LM_GetProcessId()) {
			CloseHandle(proc->handle);
			proc->handle = (HANDLE)NULL;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{

	}
#	endif

	proc->pid = (lm_pid_t)LM_BAD;
}

LM_API lm_size_t
LM_GetProcessPath(lm_tchar_t *pathbuf,
		  lm_size_t   maxlen)
{
	lm_size_t len = 0;

	if (!pathbuf || !maxlen)
		return len;

#	if LM_OS == LM_OS_WIN
	{
		HMODULE hModule = GetModuleHandle(NULL);
		if (!hModule)
		return chr_count;

		len = (lm_size_t)GetModuleFileName(hModule, pathbuf, maxlen);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_process_t proc;

		if (LM_OpenProcess(&proc)) {
			len = LM_GetProcessPathEx(proc, pathbuf, maxlen);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	if (len) {
		if (len == maxlen)
			--len;
		
		pathbuf[len] = '\x00';
	}

	return len;
}

LM_API lm_size_t
LM_GetProcessPathEx(lm_process_t proc,
		    lm_tchar_t  *pathbuf,
		    lm_size_t    maxlen)
{
	lm_size_t len = 0;

	if (!_LM_CheckProcess(proc) || !pathbuf || !maxlen)
		return len;
	
#	if LM_OS == LM_OS_WIN
	{
		len = (lm_size_t)GetModuleFileNameEx(proc.handle, NULL,
						     pathbuf, maxlen);
	}
#	elif LM_OS == LM_OS_LINUX
	{
		lm_tchar_t exe_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
		LM_SNPRINTF(exe_path, LM_ARRLEN(exe_path) - 1,
			    "%s/%d/exe", LM_PROCFS, proc.pid);
		
		len = (lm_size_t)readlink(exe_path, pathbuf, maxlen);
		if (len == (lm_size_t)-1)
			len = 0;
	}
#	elif LM_OS == LM_OS_BSD
	{
		struct procstat *ps;
		
		ps = procstat_open_sysctl();
		if (ps) {
			unsigned int nprocs = 0;
			struct kinfo_proc *procs = procstat_getprocs(
				ps, KERN_PROC_PID,
				pid, &nprocs
			);

			if (procs && nprocs) {
				if (procstat_getpathname(ps, pproc, pathbuf, maxlen))
					len = LM_STRLEN(proc_path);

				procstat_freeprocs(ps, procs);

				ret = LM_TRUE;
			}

			procstat_close(ps);
		}
	}
#	endif

	if (len) {
		if (len == maxlen)
			--len;
		
		pathbuf[len] = '\x00';
	}

	return len;
}

LM_API lm_size_t
LM_GetProcessName(lm_tchar_t *namebuf,
		  lm_size_t   maxlen);

LM_API lm_size_t
LM_GetProcessNameEx(lm_process_t proc,
		    lm_tchar_t  *namebuf,
		    lm_size_t    maxlen);

LM_API lm_size_t
LM_GetProcessBits(lm_void_t);

LM_API lm_size_t
LM_GetProcessBitsEx(lm_process_t proc);

/****************************************/

#endif
