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

typedef struct {
	lm_module_t *modbuf;
	lm_tstring_t modstr;
	lm_size_t    len;
} _lm_get_mod_t;

typedef struct {
	lm_module_t  mod;
	lm_tstring_t pathbuf;
	lm_size_t    maxlen;
	lm_size_t    len;
} _lm_get_mod_path_t;

typedef struct {
	lm_address_t addr;
	lm_page_t   *pagebuf;
} _lm_get_page_t;

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
	lm_tchar_t  c;
	ssize_t     rdsize;
	lm_tchar_t *filebuf = (lm_tchar_t *)LM_NULL;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return total;
	
	while ((rdsize = read(fd, &c, sizeof(c)) > 0)) {
		lm_tchar_t *old_filebuf;

		old_filebuf = filebuf;
		filebuf = LM_CALLOC(total + 2, sizeof(c));
		if (old_filebuf) {
			if (filebuf)
				LM_STRNCPY(filebuf, old_filebuf, total);
			LM_FREE(old_filebuf);
		}

		if (!filebuf) {
			total = 0;
			break;
		}

		filebuf[total++] = c;
		filebuf[total] = LM_STR('\x00');
	}

	if (filebuf) {
		filebuf[total] = LM_STR('\x00');
		*pfilebuf = filebuf;
	}

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
						entry.th32ProcessID
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

			if (pid || (!pid && !LM_STRCMP(pdirent->d_name,
						       LM_STR("0")))) {
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

	path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));

	if (!path)
		return LM_FALSE;

	if (LM_OpenProcessEx(pid, &proc)) {
		lm_size_t len;

		len = LM_GetProcessPathEx(proc,	path, LM_PATH_MAX - 1);
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

	return ret;
}

LM_API lm_pid_t
LM_GetProcessId(lm_void_t)
{
	lm_pid_t pid = (lm_pid_t)LM_BAD;

#	if LM_OS == LM_OS_WIN
	{
		pid = GetCurrentProcessId();
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
		}

		CloseHandle(hSnap);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *status_buf;
		lm_tchar_t  status_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
		lm_tchar_t *ptr;

		LM_SNPRINTF(status_path, LM_ARRLEN(status_path) - 1,
			    LM_STR("%s/%d/status"), LM_STR(LM_PROCFS), pid);
		
		if (!_LM_OpenFileBuf(status_path, &status_buf))
			return ppid;

		ptr = LM_STRSTR(status_buf, LM_STR("\nPPid:\t"));

		if (ptr) {
			ptr = LM_STRCHR(ptr, LM_STR('\t'));
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
			return len;

		len = (lm_size_t)GetModuleFileName(hModule, pathbuf, maxlen - 1);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_process_t proc;

		if (LM_OpenProcess(&proc)) {
			len = LM_GetProcessPathEx(proc, pathbuf, maxlen - 1);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	if (len)
		pathbuf[len] = LM_STR('\x00');

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
						     pathbuf, maxlen - 1);
	}
#	elif LM_OS == LM_OS_LINUX
	{
		lm_tchar_t exe_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };
		LM_SNPRINTF(exe_path, LM_ARRLEN(exe_path) - 1,
			    LM_STR("%s/%d/exe"), LM_STR(LM_PROCFS), proc.pid);
		
		len = (lm_size_t)readlink(exe_path, pathbuf, maxlen - 1);
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
				proc.pid, &nprocs
			);

			if (procs && nprocs) {
				if (!procstat_getpathname(ps, procs,
							  pathbuf, maxlen - 1))
					len = LM_STRLEN(pathbuf);

				procstat_freeprocs(ps, procs);
			}

			procstat_close(ps);
		}
	}
#	endif

	if (len)
		pathbuf[len] = LM_STR('\x00');

	return len;
}

LM_API lm_size_t
LM_GetProcessName(lm_tchar_t *namebuf,
		  lm_size_t   maxlen)
{
	lm_size_t len = 0;

#	if LM_OS == LM_OS_WIN
	{
		lm_tchar_t *path;
		lm_size_t   pathlen;

		path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));

		if (!path)
			return len;
		
		if (LM_GetProcessPath(path, LM_PATH_MAX)) {
			lm_tchar_t *tmp;
			lm_tchar_t *ptr = (lm_tchar_t *)LM_NULL;

			for (tmp = path;
			     tmp = LM_STRCHR(tmp, LM_STR('\\'));
			     tmp = &tmp[1])
				ptr = tmp;
			
			if (ptr) {
				ptr = &ptr[1];
				len = LM_STRLEN(ptr);
				if (len >= maxlen)
					len = maxlen - 1;
				
				LM_STRNCPY(namebuf, ptr, len);
				namebuf[len] = LM_STR('\x00');
			}
		}

		LM_FREE(path);
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_process_t proc;
		if (LM_OpenProcess(&proc)) {
			len = LM_GetProcessNameEx(proc, namebuf, maxlen);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	return len;
}

LM_API lm_size_t
LM_GetProcessNameEx(lm_process_t proc,
		    lm_tchar_t  *namebuf,
		    lm_size_t    maxlen)
{
	lm_size_t len = 0;

	if (!_LM_CheckProcess(proc) || !namebuf || !maxlen)
		return len;

#	if LM_OS == LM_OS_WIN
	{
		len = (lm_size_t)GetModuleBaseName(proc.handle, NULL, namebuf, maxlen - 1);
		if (len)
			namebuf[len] = LM_STR('\x00');
	}
#	elif LM_OS == LM_OS_LINUX
	{
		lm_tchar_t *filebuf;
		lm_tchar_t comm_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

		LM_SNPRINTF(comm_path, LM_ARRLEN(comm_path) - 1,
			    LM_STR("%s/%d/comm"), LM_STR(LM_PROCFS), proc.pid);
		
		len = _LM_OpenFileBuf(comm_path, &filebuf);

		if (len) {
			--len;

			if (len >= maxlen)
				len = maxlen - 1;
			
			LM_STRNCPY(namebuf, filebuf, len);
			namebuf[len] = LM_STR('\x00');

			_LM_CloseFileBuf(&filebuf);
		}
	}
#	elif LM_OS == LM_OS_BSD
	{
		struct procstat *ps;
		
		ps = procstat_open_sysctl();
		if (ps) {
			unsigned int nprocs = 0;
			struct kinfo_proc *procs = procstat_getprocs(
				ps, KERN_PROC_PID,
				proc.pid, &nprocs
			);

			if (procs && nprocs) {
				len = LM_STRLEN(procs->ki_comm);
				if (len > maxlen)
					len = maxlen - 1;
				
				LM_STRNCPY(namebuf, procs->ki_comm, len);
				namebuf[len] = LM_STR('\x00');

				procstat_freeprocs(ps, procs);
			}

			procstat_close(ps);
		}
	}
#	endif

	return len;
}

LM_API lm_size_t
LM_GetSystemBits(lm_void_t)
{
	lm_size_t bits = 0;

#	if LM_OS == LM_OS_WIN
	{
		SYSTEM_INFO sysinfo = { 0 };

		GetNativeSystemInfo(&sysinfo);
		switch (sysinfo.wProcessorArchitecture)
		{
		case PROCESSOR_ARCHITECTURE_INTEL:
			bits = 32;
			break;
		case PROCESSOR_ARCHITECTURE_AMD64:
			bits = 64;
			break;
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		struct utsname utsbuf;

		if (uname(&utsbuf))
			return bits;
		
		if (LM_STRCMP(utsbuf.machine, "x86_32"))
			bits = 32;
		else if (LM_STRCMP(utsbuf.machine, "x86_64"))
			bits = 64;
	}
#	endif

	return bits;
}

LM_API lm_size_t
LM_GetProcessBits(lm_void_t)
{
	return (lm_size_t)LM_BITS;
}

LM_API lm_size_t
LM_GetProcessBitsEx(lm_process_t proc)
{
	lm_size_t bits = 0;

	if (!_LM_CheckProcess(proc))
		return bits;

#	if LM_OS == LM_OS_WIN
	{
		BOOL IsWow64;
		BOOL Check;
		lm_size_t sysbits;

		if (!IsWow64Process(proc.handle, &IsWow64))
			return bits;

		sysbits = LM_GetSystemBits();

		if (sysbits == 32 || IsWow64)
			bits = 32;
		else if (sysbits == 64)
			bits = 64;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *path;

		path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
		if (!path)
			return bits;
		
		if (LM_GetProcessPathEx(proc, path, LM_PATH_MAX)) {
			int fd;

			fd = open(path, O_RDONLY);
			if (fd != -1) {
				unsigned char elf_num;

				/*
				 * 32 bits: 0x7F, ELF, 1
				 * 64 bits: 0x7F, ELF, 2
				 */

				lseek(fd, 4, SEEK_SET);
				if (read(fd, &elf_num, sizeof(elf_num)) > 0 &&
				    (elf_num == 1 || elf_num == 2))
					bits = elf_num * 32;
				
				close(fd);
			}
		}

		LM_FREE(path);
		
	}
#	endif

	return bits;
}

/****************************************/

LM_API lm_bool_t
LM_EnumModules(lm_bool_t(*callback)(lm_module_t  mod,
				    lm_tstring_t path,
				    lm_void_t   *arg),
	       lm_void_t *arg)
{
	lm_byte_t ret = LM_FALSE;
	lm_process_t proc;

	if (!callback)
		return ret;

	LM_OpenProcess(&proc);
	ret = LM_EnumModulesEx(proc, callback, arg);
	LM_CloseProcess(&proc);

	return ret;
}

LM_API lm_bool_t
LM_EnumModulesEx(lm_process_t proc,
		 lm_bool_t  (*callback)(lm_module_t  mod,
					lm_tstring_t path,
					lm_void_t   *arg),
		 lm_void_t   *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_CheckProcess(proc) || !callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		HANDLE hSnap;

		hSnap = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			proc.pid
		);

		if (hSnap != INVALID_HANDLE_VALUE) {
			MODULEENTRY32 entry;
			entry.dwSize = sizeof(MODULEENTRY32);

			if (Module32First(hSnap, &entry)) {
				do {
					lm_module_t mod;

					mod.base = (lm_address_t)(
						entry.modBaseAddr
					);
					mod.size = (lm_size_t)(
						entry.modBaseSize
					);
					mod.end  = (lm_address_t)(
						&((lm_byte_t *)mod.base)[
							mod.size
						]
					);

					if (callback(mod,
						     entry.szExePath,
						     arg) == LM_FALSE)
						break;
				} while (Module32Next(hSnap, &entry));

				ret = LM_TRUE;
			}

			CloseHandle(hSnap);
		}
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *maps_buf;
		lm_tchar_t *ptr;
		lm_tchar_t maps_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

#		if LM_OS == LM_OS_LINUX
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path) - 1,
			    LM_STR("%s/%d/maps"), LM_PROCFS, proc.pid);
#		elif LM_OS == LM_OS_BSD
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path) - 1,
			    LM_STR("%s/%d/map"), LM_PROCFS, proc.pid);
#		endif
		
		if (!_LM_OpenFileBuf(maps_path, &maps_buf))
			return ret;

		ret = LM_TRUE;

		for (ptr = maps_buf;
		     ptr && (ptr = LM_STRCHR(ptr, LM_STR('/')));
		     ptr = LM_STRCHR(ptr, LM_STR('\n'))) {
			lm_tchar_t *tmp;
			lm_tchar_t *holder;
			lm_tchar_t *path;
			lm_size_t   pathlen;
			lm_module_t mod;

#			if LM_OS == LM_OS_LINUX
			tmp = LM_STRCHR(ptr, LM_STR('\n'));
#			elif LM_OS == LM_OS_BSD
			tmp = LM_STRCHR(ptr, LM_STR(' ')); /* TOFIX: Won't work on paths that have spaces */
#			endif
			pathlen = (lm_size_t)(
				((lm_uintptr_t)tmp - (lm_uintptr_t)ptr) /
				sizeof(tmp[0])
			);
			
			path = LM_CALLOC(pathlen + 1, sizeof(lm_tchar_t));
			if (!path) {
				ret = LM_FALSE;
				break;
			}

			LM_STRNCPY(path, ptr, pathlen);
			path[pathlen] = LM_STR('\x00');

			holder = maps_buf;
			for (tmp = maps_buf;
			     (lm_uintptr_t)(
				     tmp = LM_STRCHR(tmp, LM_STR('\n'))
			     ) < (lm_uintptr_t)ptr;
			     tmp = &tmp[1])
				holder = &tmp[1];
			
			mod.base = (lm_address_t)LM_STRTOP(holder, NULL, 16);

			holder = ptr;
			for (tmp = maps_buf;
			     (tmp = LM_STRSTR(tmp, path));
			     tmp = &tmp[1])
				holder = tmp;
			
			ptr = holder;

			holder = maps_buf;
			for (tmp = maps_buf;
			     (lm_uintptr_t)(
				     tmp = LM_STRCHR(tmp, LM_STR('\n'))
			     ) < (lm_uintptr_t)ptr;
			     tmp = &tmp[1])
				holder = &tmp[1];

#			if LM_OS == LM_OS_LINUX
			holder = LM_STRCHR(holder, LM_STR('-'));
#			elif LM_OS == LM_OS_BSD
			holder = LM_STRSTR(holder, LM_STR(" 0x"));
#			endif
			holder = &holder[1];

			mod.end = (lm_address_t)LM_STRTOP(holder, NULL, 16);
			mod.size = (
				(lm_uintptr_t)mod.end - (lm_uintptr_t)mod.base
			);

			{
				lm_bool_t cbret;

				cbret = callback(mod, path, arg);
				LM_FREE(path);

				if (cbret == LM_FALSE)
					break;
			}
		}

		_LM_CloseFileBuf(&maps_buf);
	}
#	endif

	return ret;
}

static lm_bool_t
_LM_GetModuleCallback(lm_module_t  mod,
		      lm_tstring_t path,
		      lm_void_t   *arg)
{
	_lm_get_mod_t *parg = (_lm_get_mod_t *)arg;
	lm_size_t      pathlen;
	
	pathlen = LM_STRLEN(path);

	if (pathlen >= parg->len) {
		if (!LM_STRCMP(&path[pathlen - parg->len], parg->modstr)) {
			*(parg->modbuf) = mod;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

LM_API lm_bool_t
LM_GetModule(lm_tstring_t modstr,
	     lm_module_t *modbuf)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_mod_t arg;

	if (!modstr || !modbuf)
		return ret;

	arg.modbuf = modbuf;
	arg.modbuf->base = (lm_address_t)LM_BAD;
	arg.modbuf->size = 0;
	arg.modbuf->end  = (lm_address_t)LM_BAD;
	arg.modstr = modstr;
	arg.len = LM_STRLEN(arg.modstr);

	ret = LM_EnumModules(_LM_GetModuleCallback, (lm_void_t *)&arg);

	return ret;
}

LM_API lm_bool_t
LM_GetModuleEx(lm_process_t proc,
	       lm_tstring_t modstr,
	       lm_module_t *modbuf)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_mod_t arg;

	if (!modstr || !modbuf)
		return ret;

	arg.modbuf = modbuf;
	arg.modbuf->base = (lm_address_t)LM_BAD;
	arg.modbuf->size = 0;
	arg.modbuf->end  = (lm_address_t)LM_BAD;
	arg.modstr = modstr;
	arg.len = LM_STRLEN(arg.modstr);

	ret = LM_EnumModulesEx(proc, _LM_GetModuleCallback, (lm_void_t *)&arg);

	return ret;
}

static lm_bool_t
_LM_GetModulePathCallback(lm_module_t  mod,
			  lm_tstring_t path,
			  lm_void_t   *arg)
{
	_lm_get_mod_path_t *parg = (_lm_get_mod_path_t *)arg;
	
	if (parg->mod.base == mod.base) {
		parg->len = LM_STRLEN(path);
		if (parg->len >= parg->maxlen)
			parg->len = parg->maxlen - 1;
		LM_STRNCPY(parg->pathbuf, path, parg->len);
		parg->pathbuf[parg->len] = LM_STR('\x00');
	}

	return LM_TRUE;
}

LM_API lm_size_t
LM_GetModulePath(lm_module_t mod,
		 lm_tchar_t *pathbuf,
		 lm_size_t   maxlen)
{
	_lm_get_mod_path_t arg;

	arg.mod     = mod;
	arg.pathbuf = pathbuf;
	arg.maxlen  = maxlen;
	arg.len     = 0;

	if (!arg.pathbuf || !arg.maxlen)
		return arg.len;

	LM_EnumModules(_LM_GetModulePathCallback, (lm_void_t *)&arg);

	return arg.len;
}

LM_API lm_size_t
LM_GetModulePathEx(lm_process_t proc,
		   lm_module_t  mod,
		   lm_tchar_t  *pathbuf,
		   lm_size_t    maxlen)
{
	_lm_get_mod_path_t arg;
	
	arg.mod     = mod;
	arg.pathbuf = pathbuf;
	arg.maxlen  = maxlen;
	arg.len     = 0;

	if (!arg.pathbuf || !arg.maxlen)
		return arg.len;

	LM_EnumModulesEx(proc, _LM_GetModulePathCallback, (lm_void_t *)&arg);

	return arg.len;
}

LM_API lm_size_t
LM_GetModuleName(lm_module_t mod,
		 lm_tchar_t *namebuf,
		 lm_size_t   maxlen)
{
	lm_size_t   len = 0;
	lm_tchar_t *path;

	if (!namebuf || !maxlen)
		return len;

	path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!path)
		return len;

	if (LM_GetModulePath(mod, path, LM_PATH_MAX)) {
		lm_tchar_t  sep;
		lm_tchar_t *ptr;
		lm_tchar_t *holder;

#		if LM_OS == LM_OS_WIN
		sep = LM_STR('\\');
#		elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
		sep = LM_STR('/');
#		endif

		holder = path;

		for (ptr = path; (ptr = LM_STRCHR(ptr, sep)); ptr = &ptr[1])
			holder = &ptr[1];
		
		len = LM_STRLEN(holder);
		if (len >= maxlen)
			len = maxlen - 1;
		
		LM_STRNCPY(namebuf, holder, len);
		namebuf[len] = LM_STR('\x00');
	}

	LM_FREE(path);
	return len;
}

LM_API lm_size_t
LM_GetModuleNameEx(lm_process_t proc,
		   lm_module_t  mod,
		   lm_tchar_t  *namebuf,
		   lm_size_t    maxlen)
{
	lm_size_t   len = 0;
	lm_tchar_t *path;

	if (!namebuf || !maxlen)
		return len;

	path = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	if (!path)
		return len;

	if (LM_GetModulePathEx(proc, mod, path, LM_PATH_MAX)) {
		lm_tchar_t  sep;
		lm_tchar_t *ptr;
		lm_tchar_t *holder;

#		if LM_OS == LM_OS_WIN
		sep = LM_STR('\\');
#		elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
		sep = LM_STR('/');
#		endif

		holder = path;

		for (ptr = path; (ptr = LM_STRCHR(ptr, sep)); ptr = &ptr[1])
			holder = &ptr[1];
		
		len = LM_STRLEN(holder);
		if (len >= maxlen)
			len = maxlen - 1;
		
		LM_STRNCPY(namebuf, holder, len);
		namebuf[len] = LM_STR('\x00');
	}

	LM_FREE(path);
	return len;
}

LM_API lm_bool_t
LM_LoadModule(lm_tstring_t path,
	      lm_module_t *mod);

LM_API lm_bool_t
LM_LoadModuleEx(lm_process_t proc,
		lm_tstring_t path,
		lm_module_t *mod);

LM_API lm_bool_t
LM_UnloadModule(lm_module_t mod);

LM_API lm_bool_t
LM_UnloadModuleEx(lm_process_t proc,
		  lm_module_t  mod);

LM_API lm_address_t
LM_GetSymbol(lm_module_t mod);

LM_API lm_address_t
LM_GetSymbolEx(lm_process_t proc,
	       lm_module_t  mod);

/****************************************/

LM_API lm_bool_t
LM_EnumPages(lm_bool_t(*callback)(lm_page_t  page,
				  lm_void_t *arg),
	     lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		lm_address_t addr;
		MEMORY_BASIC_INFORMATION mbi;

		for (addr = (lm_address_t)0;
		     VirtualQuery(addr, &mbi, sizeof(mbi));
		     addr = (lm_address_t)(
			     &((lm_byte_t *)mbi.BaseAddress)[mbi.RegionSize]
		     )) {
			lm_page_t page;

			page.base  = (lm_address_t)mbi.BaseAddress;
			page.size  = (lm_size_t)mbi.RegionSize;
			page.end   = (lm_address_t)(
				&((lm_byte_t *)page.base)[page.size]
			);
			page.prot  = mbi.Protect;
			page.flags = mbi.Type;

			if (callback(page, arg) == LM_FALSE)
				break;
		}

		ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_process_t proc;

		if (LM_OpenProcess(&proc)) {
			ret = LM_EnumPagesEx(proc, callback, arg);
			LM_CloseProcess(&proc);
		}
	}
#	endif

	return ret;
}

LM_API lm_bool_t
LM_EnumPagesEx(lm_process_t proc,
	       lm_bool_t  (*callback)(lm_page_t  page,
				      lm_void_t *arg),
	       lm_void_t   *arg)
{
	lm_bool_t ret = LM_FALSE;

	if (!_LM_CheckProcess(proc) || !callback)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		lm_address_t addr;
		MEMORY_BASIC_INFORMATION mbi;

		for (addr = (lm_address_t)0;
		     VirtualQueryEx(proc.handle, addr, &mbi, sizeof(mbi));
		     addr = (lm_address_t)(
			     &((lm_byte_t *)mbi.BaseAddress)[mbi.RegionSize]
		     )) {
			lm_page_t page;

			page.base  = (lm_address_t)mbi.BaseAddress;
			page.size  = (lm_size_t)mbi.RegionSize;
			page.end   = (lm_address_t)(
				&((lm_byte_t *)page.base)[page.size]
			);
			page.prot  = mbi.Protect;
			page.flags = mbi.Type;

			if (callback(page, arg) == LM_FALSE)
				break;
		}

		ret = LM_TRUE;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD
	{
		lm_tchar_t *maps_buf;
		lm_tchar_t *ptr;
		lm_tchar_t maps_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

#		if LM_OS == LM_OS_LINUX
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path) - 1,
			    LM_STR("%s/%d/maps"), LM_PROCFS, proc.pid);
#		elif LM_OS == LM_OS_BSD
		LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path) - 1,
			    LM_STR("%s/%d/map"), LM_PROCFS, proc.pid);
#		endif
		
		if (!_LM_OpenFileBuf(maps_path, &maps_buf))
			return ret;

		ret = LM_TRUE;

		for (ptr = maps_buf; ptr; ptr = LM_STRCHR(ptr, LM_STR('\n'))) {
			lm_page_t page;

			if (ptr != maps_buf)
				ptr = &ptr[1];
			
			page.base = (lm_address_t)LM_STRTOP(ptr, NULL, 16);

#			if LM_OS == LM_OS_LINUX
			ptr = LM_STRCHR(ptr, LM_STR('-'));
#			elif LM_OS == LM_OS_BSD
			ptr = LM_STRSTR(ptr, LM_STR(" 0x"));
#			endif

			ptr = &ptr[1];

			page.end = (lm_address_t)LM_STRTOP(ptr, NULL, 16);
			page.size = (lm_size_t)(
				(lm_uintptr_t)page.end - 
				(lm_uintptr_t)page.base
			);

			page.prot  = 0;
			page.flags = 0;

#			if LM_OS == LM_OS_LINUX
			{
				lm_size_t i;

				ptr = LM_STRCHR(ptr, LM_STR(' '));
				ptr = &ptr[1];

				for (i = 0; i < 4; ++i) {
					switch (ptr[i]) {
					case LM_STR('r'):
						page.prot |= PROT_READ;
						break;
					case LM_STR('w'):
						page.prot |= PROT_WRITE;
						break;
					case LM_STR('x'):
						page.prot |= PROT_EXEC;
						break;
					case LM_STR('p'):
						page.flags = MAP_PRIVATE;
						break;
					case LM_STR('s'):
						page.flags = MAP_SHARED;
						break;
					}
				}
			}
#			elif LM_OS == LM_OS_BSD
			{
				lm_size_t i;

				for (i = 0; i < 4; ++i) {
					ptr = LM_STRCHR(ptr, LM_STR(' '));
					ptr = &ptr[1];
				}

				for (i = 0; i < 3; ++i) {
					switch (ptr[i]) {
					case LM_STR('r'):
						page.prot |= PROT_READ;
						break;
					case LM_STR('w'):
						page.prot |= PROT_WRITE;
						break;
					case LM_STR('x'):
						page.prot |= PROT_EXEC;
						break;
					}
				}
			}
#			endif

			if (callback(page, arg) == LM_FALSE)
				break;
		}

		_LM_CloseFileBuf(&maps_buf);
	}
#	endif

	return ret;
}

static lm_bool_t
_LM_GetPageCallback(lm_page_t  page,
		    lm_void_t *arg)
{
	_lm_get_page_t *parg = (_lm_get_page_t *)arg;
	
	if ((lm_uintptr_t)parg->addr >= (lm_uintptr_t)page.base &&
	    (lm_uintptr_t)parg->addr < (lm_uintptr_t)page.end) {
		*parg->pagebuf = page;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_bool_t
LM_GetPage(lm_address_t addr,
	   lm_page_t   *page)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_page_t arg;

	if (!addr || !page)
		return ret;

	arg.addr = addr;
	arg.pagebuf = page;
	arg.pagebuf->base = (lm_address_t)LM_BAD;
	arg.pagebuf->size = 0;
	arg.pagebuf->end  = (lm_address_t)LM_BAD;

	LM_EnumPages(_LM_GetPageCallback, (lm_void_t *)&arg);

	ret = page->size > 0 ? LM_TRUE : LM_FALSE;
	return ret;
}

LM_API lm_bool_t
LM_GetPageEx(lm_process_t proc,
	     lm_address_t addr,
	     lm_page_t   *page)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_page_t arg;

	if (!_LM_CheckProcess(proc) || !addr || !page)
		return ret;

	arg.addr = addr;
	arg.pagebuf = page;
	arg.pagebuf->base = (lm_address_t)LM_BAD;
	arg.pagebuf->size = 0;
	arg.pagebuf->end  = (lm_address_t)LM_BAD;

	LM_EnumPagesEx(proc, _LM_GetPageCallback, (lm_void_t *)&arg);

	ret = page->size > 0 ? LM_TRUE : LM_FALSE;
	return ret;
}

/****************************************/

LM_API lm_size_t
LM_ReadMemory(lm_address_t src,
	      lm_byte_t   *dst,
	      lm_size_t    size)
{
	lm_size_t i;

	for (i = 0; i < size; ++i)
		dst[i] = ((lm_byte_t *)src)[i];

	return i;
}

LM_API lm_size_t
LM_ReadMemoryEx(lm_process_t proc,
		lm_address_t src,
		lm_byte_t   *dst,
		lm_size_t    size)
{
	lm_size_t rdsize = 0;

	if (!_LM_CheckProcess(proc) || !src || !dst || !size)
		return rdsize;
	
#	if LM_OS == LM_OS_WIN
	{
		rdsize = (lm_size_t)ReadProcessMemory(proc.handle, src, dst,
						      size, NULL);
	}
#	elif LM_OS == LM_OS_LINUX
	{
		struct iovec iosrc = { 0 };
		struct iovec iodst = { 0 };
		iodst.iov_base = dst;
		iodst.iov_len  = size;
		iosrc.iov_base = src;
		iosrc.iov_len  = size;
		rdsize = (lm_size_t)process_vm_readv(proc.pid, &iodst, 1,
						     &iosrc, 1, 0);

		if (rdsize == (lm_size_t)-1)
			rdsize = 0;
	}
#	elif LM_OS == LM_OS_BSD
	{
		int fd;
		lm_tchar_t mem_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

		LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path) - 1,
			    LM_STR("%s/%d/maps"), LM_STR(LM_PROCFS), proc.pid);
		
		fd = open(mem_path, O_RDONLY);
		if (fd == -1)
			return rdsize;
		
		rdsize = (lm_size_t)pread(fd, dst, size, (off_t)src);
		close(fd);

		if (rdsize == (lm_size_t)-1)
			rdsize = 0;
	}
#	endif

	return rdsize;
}

LM_API lm_size_t
LM_WriteMemory(lm_address_t dst,
	       lm_bstring_t src,
	       lm_size_t    size)
{
	lm_size_t i;

	for (i = 0; i < size; ++i)
		((lm_byte_t *)dst)[i] = src[i];

	return i;
}

LM_API lm_size_t
LM_WriteMemoryEx(lm_process_t proc,
		 lm_address_t dst,
		 lm_bstring_t src,
		 lm_size_t    size)
{
	lm_size_t wrsize = 0;

	if (!_LM_CheckProcess(proc) || !dst || !src || !size)
		return wrsize;

#	if LM_OS == LM_OS_WIN
	{
		wrsize = (lm_size_t)WriteProcessMemory(proc.handle, dst, src,
						       size, NULL);
	}
#	elif LM_OS == LM_OS_LINUX
	{
		struct iovec iosrc = { 0 };
		struct iovec iodst = { 0 };
		iosrc.iov_base = src;
		iosrc.iov_len = size;
		iodst.iov_base = dst;
		iodst.iov_len = size;
		wrsize = (lm_size_t)process_vm_writev(proc.pid, &iosrc, 1,
						      &iodst, 1, 0);

		if (wrsize == (lm_size_t)-1)
			wrsize = 0;
	}
#	elif LM_OS == LM_OS_BSD
	{
		int fd;
		lm_tchar_t mem_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

		LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path) - 1,
			    LM_STR("%s/%d/maps"), LM_STR(LM_PROCFS), proc.pid);
		
		fd = open(mem_path, O_RDONLY);
		if (fd == -1)
			return wrsize;
		
		wrsize = (lm_size_t)pwrite(fd, src, size, (off_t)dst);
		close(fd);

		if (wrsize == (lm_size_t)-1)
			wrsize = 0;
	}
#	endif

	return wrsize;
}

LM_API lm_size_t
LM_SetMemory(lm_byte_t *dst,
	     lm_byte_t  byte,
	     lm_size_t  size)
{
	lm_size_t i;

	for (i = 0; i < size; ++i)
		dst[i] = byte;
	
	return i;
}

LM_API lm_size_t
LM_SetMemoryEx(lm_process_t proc,
	       lm_address_t dst,
	       lm_byte_t    byte,
	       lm_size_t    size)
{
	lm_size_t  wrsize = 0;
	lm_byte_t *data;

	data = LM_MALLOC(size);
	if (!data)
		return wrsize;

	if (LM_SetMemory(data, byte, size) != size)
		return wrsize;
	
	wrsize = LM_WriteMemoryEx(proc, dst, data, size);

	LM_FREE(data);
	return wrsize;
}

LM_API lm_size_t
LM_ProtMemory(lm_address_t addr,
	      lm_prot_t    prot,
	      lm_size_t    size);

LM_API lm_size_t
LM_ProtMemoryEx(lm_process_t proc,
		lm_address_t addr,
		lm_prot_t    prot,
		lm_size_t    size);

LM_API lm_address_t
LM_AllocMemory(lm_prot_t prot,
	       lm_size_t size);

LM_API lm_address_t
LM_AllocMemoryEx(lm_process_t proc,
		 lm_prot_t    prot,
		 lm_size_t    size);

LM_API lm_void_t
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size);

LM_API lm_void_t
LM_FreeMemoryEx(lm_process_t proc,
		lm_address_t alloc,
		lm_size_t    size);

LM_API lm_address_t
LM_DataScan(lm_bstring_t data,
	    lm_size_t    size,
	    lm_address_t start,
	    lm_address_t stop)
{
	/* TODO: Protect Search Region as XRW */
	lm_address_t match = (lm_address_t)LM_BAD;
	lm_byte_t *ptr;

	if (!data || !size || !start || !stop || 
	    (lm_uintptr_t)start >= (lm_uintptr_t)stop)
		return match;

	for (ptr = (lm_byte_t *)start; ptr != stop; ptr = &ptr[1]) {
		lm_size_t i;
		lm_bool_t check = LM_TRUE;

		for (i = 0; check && i < size; ++i)
			check = (ptr[i] == data[i]) ? check : LM_FALSE;
		
		if (!check)
			continue;
		
		match = (lm_address_t)ptr;
		break;
	}

	return match;
}

LM_API lm_address_t
LM_DataScanEx(lm_process_t proc,
	      lm_bstring_t data,
	      lm_size_t    size,
	      lm_address_t start,
	      lm_address_t stop);

LM_API lm_address_t
LM_PatternScan(lm_bstring_t pattern,
	       lm_tstring_t mask,
	       lm_address_t start,
	       lm_address_t stop);

LM_API lm_address_t
LM_PatternScanEx(lm_process_t proc,
		 lm_bstring_t pattern,
		 lm_tstring_t mask,
		 lm_address_t start,
		 lm_address_t stop);

LM_API lm_address_t
LM_SigScan(lm_tstring_t sig,
	   lm_address_t start,
	   lm_address_t stop);

LM_API lm_address_t
LM_SigScanEx(lm_process_t proc,
	     lm_tstring_t sig,
	     lm_address_t start,
	     lm_address_t stop);

/****************************************/

#endif
