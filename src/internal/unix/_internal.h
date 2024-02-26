/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <regex.h>
#include <link.h>
#include <elf.h>

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
