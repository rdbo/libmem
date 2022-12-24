#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem.h>

#define LM_PRIVATE static

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

#endif
