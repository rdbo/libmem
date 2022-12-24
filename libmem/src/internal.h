#ifndef LIBMEM_INTERNAL_H
#define LIBMEM_INTERNAL_H

#include <libmem.h>

#define LM_PRIVATE static

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#if LM_OS == LM_OS_WIN
#	include <TlHelp32.h>
#	include <Psapi.h>
#	if LM_LANG == LM_LANG_CPP
#		include <LIEF/PE.hpp>
#	endif
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
#	if LM_LANG != LM_LANG_CPP /* conflicts with LIEF */
#		include <link.h>
#		include <elf.h>
#	else
#		include <LIEF/ELF.hpp>
#	endif
#	if LM_OS == LM_OS_BSD
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
