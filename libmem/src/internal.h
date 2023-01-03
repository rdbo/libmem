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

#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem/libmem.h>

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#if LM_OS == LM_OS_WIN
#	include <TlHelp32.h>
#	include <Psapi.h>
#else
#	include <dirent.h>
#	include <errno.h>
#	include <sys/types.h>
#	include <unistd.h>
#	include <sys/stat.h>
#	include <sys/ptrace.h>
#	include <sys/wait.h>
#	include <sys/mman.h>
#	include <sys/user.h>
#	include <sys/syscall.h>
#	include <sys/utsname.h>
#	include <dlfcn.h>
#	include <fcntl.h>
#	include <regex.h>
#	include <link.h>
#	include <elf.h>
#	if LM_OS == LM_OS_BSD
#		include <sys/param.h>
#		include <sys/sysctl.h>
#		include <machine/reg.h>
#		include <kvm.h>
#		include <libprocstat.h>
#		include <paths.h>
#	else
#		include <sys/uio.h>
#		if LM_OS != LM_OS_ANDROID
#			include <sys/io.h>
#		endif
#	endif
#endif

LM_PRIVATE lm_pid_t
_LM_GetProcessId(lm_void_t);

LM_PRIVATE lm_pid_t
_LM_GetParentId(lm_void_t);

LM_PRIVATE lm_pid_t
_LM_GetParentIdEx(lm_pid_t pid);

LM_PRIVATE lm_size_t
_LM_GetProcessPath(lm_char_t *pathbuf,
		   lm_size_t  maxlen);

LM_PRIVATE lm_size_t
_LM_GetProcessPathEx(lm_pid_t   pid,
		     lm_char_t *pathbuf,
		     lm_size_t  maxlen);

LM_PRIVATE lm_size_t
_LM_GetProcessName(lm_char_t *namebuf,
		   lm_size_t  maxlen);

LM_PRIVATE lm_size_t
_LM_GetProcessNameEx(lm_pid_t   pid,
		     lm_char_t *namebuf,
		     lm_size_t  maxlen);

LM_PRIVATE lm_size_t
_LM_GetNameFromPath(lm_char_t *path,
		    lm_char_t *namebuf,
		    lm_size_t  maxlen);

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_OpenProc(lm_process_t *pproc,
	     HANDLE       *hProcess);

LM_PRIVATE lm_void_t
_LM_CloseProc(HANDLE *handle);

LM_PRIVATE lm_size_t
_LM_GetProcessBitsEx(lm_pid_t pid);
#else
typedef struct {
	 lm_int_t      syscall_num;
	 lm_uintptr_t  arg0;
	 lm_uintptr_t  arg1;
	 lm_uintptr_t  arg2;
	 lm_uintptr_t  arg3;
	 lm_uintptr_t  arg4;
	 lm_uintptr_t  arg5;
} _lm_syscall_data_t;

typedef struct {
	lm_uintptr_t   func_addr;
	lm_size_t      nargs;
	lm_uintptr_t   arg0;
	lm_uintptr_t   arg1;
	lm_uintptr_t   arg2;
	lm_uintptr_t   arg3;
	lm_uintptr_t   arg4;
	lm_uintptr_t   arg5;
} _lm_libcall_data_t;

LM_PRIVATE lm_size_t
_LM_GetProcessBitsEx(lm_char_t *elfpath);

LM_PRIVATE lm_bool_t
_LM_SystemCallEx(lm_process_t       *pproc,
		 _lm_syscall_data_t *data,
		 lm_uintptr_t       *syscall_ret);

LM_PRIVATE lm_bool_t
_LM_FindLibc(lm_process_t *pproc,
	     lm_module_t  *libc_mod);

LM_PRIVATE lm_bool_t
_LM_LibraryCallEx(lm_process_t      *pproc,
		 _lm_libcall_data_t *data,
		 lm_uintptr_t       *call_ret);

LM_PRIVATE lm_bool_t
_LM_CallDlopen(lm_process_t *pproc,
	       lm_string_t   path,
	       lm_int_t      mode,
	       void        **plibhandle);

LM_PRIVATE lm_bool_t
_LM_CallDlclose(lm_process_t *pproc,
		void         *modhandle);
#endif

#endif
