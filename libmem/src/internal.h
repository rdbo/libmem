#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem.h>

#define LM_PRIVATE

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

#if LM_OS != LM_OS_WIN
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
	lm_uintptr_t   arg0;
	lm_uintptr_t   arg1;
	lm_uintptr_t   arg2;
	lm_uintptr_t   arg3;
	lm_uintptr_t   arg4;
	lm_uintptr_t   arg5;
} _lm_libcall_data_t;

LM_PRIVATE lm_bool_t
_LM_SystemCallEx(lm_process_t        proc,
		 _lm_syscall_data_t *data,
		 lm_uintptr_t       *syscall_ret);

LM_PRIVATE lm_bool_t
_LM_LibraryCallEx(lm_process_t       proc,
		 _lm_libcall_data_t *data,
		 lm_uintptr_t       *call_ret);
#endif

#endif
