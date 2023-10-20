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

#if LM_OS == LM_OS_LINUX && !defined(SYS_mmap2)
#	define SYS_mmap2 192
#endif

LM_PRIVATE lm_prot_t
_LM_GetRealProt(lm_prot_t prot)
{
	lm_prot_t real_prot;

	switch (prot) {
	case LM_PROT_NONE: real_prot = _LM_PROT_NONE; break;
	case LM_PROT_X:    real_prot = _LM_PROT_X; break;
	case LM_PROT_R:    real_prot = _LM_PROT_R; break;
	case LM_PROT_W:    real_prot = _LM_PROT_W; break;
	case LM_PROT_XR:   real_prot = _LM_PROT_XR; break;
	case LM_PROT_XW:   real_prot = _LM_PROT_XW; break;
	case LM_PROT_RW:   real_prot = _LM_PROT_RW; break;
	case LM_PROT_XRW:  real_prot = _LM_PROT_XRW; break;
	default:           real_prot = _LM_PROT_NONE; break;
	}

	return real_prot;
}

LM_PRIVATE lm_prot_t
_LM_GetProt(lm_prot_t real_prot)
{
	lm_prot_t prot;

	switch (real_prot) {
	case _LM_PROT_X:   prot = LM_PROT_X; break;
	case _LM_PROT_R:   prot = LM_PROT_R; break;
	case _LM_PROT_W:   prot = LM_PROT_W; break;
	case _LM_PROT_XR:  prot = LM_PROT_XR; break;
	case _LM_PROT_XW:  prot = LM_PROT_XW; break;
	case _LM_PROT_RW:  prot = LM_PROT_RW; break;
	case _LM_PROT_XRW: prot = LM_PROT_XRW; break;
	default:           prot = LM_PROT_NONE; break;
	}

	return prot;
}

/********************************/

LM_API lm_size_t
LM_ReadMemory(lm_address_t src,
	      lm_byte_t   *dst,
	      lm_size_t    size)
{
	lm_size_t i;

	if (src == LM_ADDRESS_BAD || dst == LM_NULLPTR || size == 0)
		return 0;

	for (i = 0; i < size; ++i)
		dst[i] = ((lm_byte_t *)src)[i];

	return i;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_ReadMemoryEx(lm_process_t *pproc,
		 lm_address_t  src,
		 lm_byte_t    *dst,
		 lm_size_t     size)
{
	lm_size_t rdsize = 0;
	HANDLE hProcess;

	if (!_LM_OpenProc(pproc->pid, &hProcess))
		return rdsize;

	if (!ReadProcessMemory(hProcess, src, dst, size, &rdsize))
		rdsize = 0;

	_LM_CloseProc(&hProcess);

	return rdsize;
}
#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
LM_PRIVATE lm_size_t
_LM_ReadMemoryEx(lm_process_t *pproc,
		 lm_address_t  src,
		 lm_byte_t    *dst,
		 lm_size_t     size)
{
	struct iovec iosrc = { 0 };
	struct iovec iodst = { 0 };
	ssize_t rdsize;

	iodst.iov_base = dst;
	iodst.iov_len  = size;
	iosrc.iov_base = (void *)src;
	iosrc.iov_len  = size;
	rdsize = (lm_size_t)process_vm_readv(pproc->pid, &iodst, 1,
					     &iosrc, 1, 0);

	if (rdsize == -1)
		return 0;

	return (lm_size_t)rdsize;
}
#else
LM_PRIVATE lm_size_t
_LM_ReadMemoryEx(lm_process_t *pproc,
		 lm_address_t  src,
		 lm_byte_t    *dst,
		 lm_size_t     size)
{
	int fd;
	lm_char_t mem_path[LM_PATH_MAX] = { 0 };
	ssize_t rdsize;

	LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path),
		    LM_STR("%s/%d/mem"), LM_PROCFS, pproc->pid);

	fd = open(mem_path, O_RDONLY);
	if (fd == -1)
		return 0;

	rdsize = pread(fd, dst, size, (off_t)src);
	close(fd);

	if (rdsize == -1)
		return 0;

	return (lm_size_t)rdsize;
}
#endif

LM_API lm_size_t
LM_ReadMemoryEx(lm_process_t *pproc,
		lm_address_t src,
		lm_byte_t   *dst,
		lm_size_t    size)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || src == LM_ADDRESS_BAD || !dst || size == 0)
		return LM_FALSE;

	return _LM_ReadMemoryEx(pproc, src, dst, size);
}

/********************************/

LM_API lm_size_t
LM_WriteMemory(lm_address_t dst,
	       lm_bytearr_t src,
	       lm_size_t    size)
{
	lm_size_t i;

	if (dst == LM_ADDRESS_BAD || !src || size == 0)
		return 0;

	for (i = 0; i < size; ++i)
		((lm_byte_t *)dst)[i] = src[i];

	return i;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_WriteMemoryEx(lm_process_t *pproc,
		  lm_address_t  dst,
		  lm_bytearr_t  src,
		  lm_size_t     size)
{
	lm_size_t wrsize = 0;
	HANDLE hProcess;
	SIZE_T written_bytes;

	if (!_LM_OpenProc(pproc->pid, &hProcess))
		return wrsize;

	if (WriteProcessMemory(hProcess, dst, src, size, &written_bytes))
		wrsize = (lm_size_t)written_bytes;

	_LM_CloseProc(&hProcess);

	return wrsize;
}
#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
LM_PRIVATE lm_size_t
_LM_WriteMemoryEx(lm_process_t *pproc,
		  lm_address_t  dst,
		  lm_bytearr_t  src,
		  lm_size_t     size)
{
	struct iovec iosrc = { 0 };
	struct iovec iodst = { 0 };
	ssize_t wrsize;

	iosrc.iov_base = src;
	iosrc.iov_len = size;
	iodst.iov_base = (void *)dst;
	iodst.iov_len = size;
	wrsize = process_vm_writev(pproc->pid, &iosrc, 1, &iodst, 1, 0);

	if (wrsize == -1)
		return 0;

	return (lm_size_t)wrsize;
}
#else
LM_PRIVATE lm_size_t
_LM_WriteMemoryEx(lm_process_t *pproc,
		  lm_address_t  dst,
		  lm_bytearr_t  src,
		  lm_size_t     size)
{
	int fd;
	lm_char_t mem_path[LM_PATH_MAX] = { 0 };
	ssize_t wrsize;

	LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path),
		    LM_STR("%s/%d/mem"), LM_PROCFS, pproc->pid);

	fd = open(mem_path, O_WRONLY);
	if (fd == -1)
		return 0;

	wrsize = pwrite(fd, src, size, (off_t)dst);
	close(fd);

	if (wrsize == -1)
		return 0;

	return (lm_size_t)wrsize;
}
#endif

LM_API lm_size_t
LM_WriteMemoryEx(lm_process_t *pproc,
		 lm_address_t  dst,
		 lm_bytearr_t  src,
		 lm_size_t     size)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || dst == LM_ADDRESS_BAD || !src || size == 0)
		return LM_FALSE;

	return _LM_WriteMemoryEx(pproc, dst, src, size);
}

/********************************/

LM_API lm_size_t
LM_SetMemory(lm_address_t dst,
	     lm_byte_t    byte,
	     lm_size_t    size)
{
	lm_size_t i;

	if (dst == LM_ADDRESS_BAD || size == 0)
		return 0;

	for (i = 0; i < size; ++i)
		*(lm_byte_t *)LM_OFFSET(dst, i) = byte;
	
	return i;
}

/********************************/

LM_API lm_size_t
LM_SetMemoryEx(lm_process_t *pproc,
	       lm_address_t  dst,
	       lm_byte_t     byte,
	       lm_size_t     size)
{
	lm_size_t  wrsize = 0;
	lm_byte_t *data;

	if (!pproc || !LM_VALID_PROCESS(pproc) || dst == LM_ADDRESS_BAD || size == 0)
		return LM_FALSE;

	data = (lm_byte_t *)LM_MALLOC(size);
	if (!data)
		return wrsize;

	if (LM_SetMemory((lm_address_t)data, byte, size) != size)
		return wrsize;
	
	wrsize = LM_WriteMemoryEx(pproc, dst, data, size);

	LM_FREE(data);
	return wrsize;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_ProtMemory(lm_address_t addr,
	       lm_size_t    size,
	       lm_prot_t    prot,
	       lm_prot_t   *oldprot)
{
	DWORD old_prot;

	if (!VirtualProtect(addr, size, _LM_GetRealProt(prot), &old_prot))
		return LM_FALSE;

	if (oldprot)
		*oldprot = _LM_GetProt((lm_prot_t)old_prot);

	return LM_TRUE;
}
#else
LM_PRIVATE lm_bool_t
_LM_ProtMemory(lm_address_t addr,
	       lm_size_t    size,
	       lm_prot_t    prot,
	       lm_prot_t   *oldprot)
{
	long pagesize;
	lm_page_t page;

	if (oldprot && !LM_GetPage(addr, &page))
		return LM_FALSE;

	pagesize = sysconf(_SC_PAGE_SIZE);
	addr = (lm_address_t)(
		(lm_uintptr_t)addr & (lm_uintptr_t)(-pagesize)
	);

	if (mprotect((void *)addr, size, _LM_GetRealProt(prot)))
		return LM_FALSE;

	if (oldprot)
		*oldprot = page.prot;

	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_ProtMemory(lm_address_t addr,
	      lm_size_t    size,
	      lm_prot_t    prot,
	      lm_prot_t   *oldprot)
{
	/* oldprot can be a null pointer */
	if (addr == LM_ADDRESS_BAD || size == 0 || !LM_VALID_PROT(prot))
		return LM_FALSE;
	
	return _LM_ProtMemory(addr, size, prot, oldprot);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_ProtMemoryEx(lm_process_t *pproc,
		 lm_address_t  addr,
		 lm_size_t     size,
		 lm_prot_t     prot,
		 lm_prot_t    *oldprot)
{
	lm_bool_t ret = LM_FALSE;
	DWORD old_prot;
	HANDLE hProcess;

	if (!_LM_OpenProc(pproc->pid, &hProcess))
		return ret;

	if (!VirtualProtectEx(hProcess, addr, size, _LM_GetRealProt(prot), &old_prot))
		goto CLOSE_RET;

	if (oldprot)
		*oldprot = _LM_GetProt((lm_prot_t)old_prot);

	ret = LM_TRUE;
CLOSE_RET:
	_LM_CloseProc(&hProcess);
	return ret;
}
#else
LM_PRIVATE lm_bool_t
_LM_ProtMemoryEx(lm_process_t *pproc,
		 lm_address_t  addr,
		 lm_size_t     size,
		 lm_prot_t     prot,
		 lm_prot_t    *oldprot)
{
	_lm_syscall_data_t data;
	lm_uintptr_t       syscall_ret = (lm_uintptr_t)-1;

	if (oldprot) {
		lm_page_t page;

		if (!LM_GetPageEx(pproc, addr, &page))
			return LM_FALSE;

		*oldprot = page.prot;
	}

#	if LM_OS == LM_OS_LINUX
	data.syscall_num = __NR_mprotect;
#	else
	data.syscall_num = SYS_mprotect;
#	endif

	data.arg0 = (lm_uintptr_t)addr; /* addr */
	data.arg1 = (lm_uintptr_t)size; /* len */
	data.arg2 = (lm_uintptr_t)_LM_GetRealProt(prot); /* prot */
	data.arg3 = data.arg4 = data.arg5 = 0;
	if (!_LM_SystemCallEx(pproc, &data, &syscall_ret))
		return LM_FALSE;

	return syscall_ret != (lm_uintptr_t)-1 ? LM_TRUE : LM_FALSE;
}
#endif

LM_API lm_bool_t
LM_ProtMemoryEx(lm_process_t *pproc,
		lm_address_t  addr,
		lm_size_t     size,
		lm_prot_t     prot,
		lm_prot_t    *oldprot)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || addr == LM_ADDRESS_BAD || !LM_VALID_PROT(prot) || size == 0)
		return LM_FALSE;

	return _LM_ProtMemoryEx(pproc, addr, size, prot, oldprot);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_address_t
_LM_AllocMemory(lm_size_t size,
		lm_prot_t prot)
{
	lm_address_t alloc;

	alloc = (lm_address_t)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, _LM_GetRealProt(prot));
	if (!alloc)
		alloc = LM_ADDRESS_BAD;

	return alloc;
}
#else
LM_PRIVATE lm_address_t
_LM_AllocMemory(lm_size_t size,
		lm_prot_t prot)
{
	lm_address_t alloc;

	alloc = (lm_address_t)(
		mmap(NULL, size, _LM_GetRealProt(prot), MAP_PRIVATE | MAP_ANON, -1, 0)
	);

	if (alloc == (lm_address_t)MAP_FAILED)
		alloc = (lm_address_t)LM_ADDRESS_BAD;

	return alloc;
}
#endif

LM_API lm_address_t
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot)
{
	if (size == 0 || !LM_VALID_PROT(prot))
		return LM_ADDRESS_BAD;

	return _LM_AllocMemory(size, prot);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_address_t
_LM_AllocMemoryEx(lm_process_t *pproc,
		  lm_size_t     size,
		  lm_prot_t     prot)
{
	lm_address_t alloc = LM_ADDRESS_BAD;
	HANDLE hProcess;

	if (!_LM_OpenProc(pproc->pid, &hProcess))
		return alloc;

	alloc = (lm_address_t)VirtualAllocEx(hProcess, NULL, size,
					     MEM_COMMIT | MEM_RESERVE, _LM_GetRealProt(prot));
	if (!alloc)
		alloc = LM_ADDRESS_BAD;

	_LM_CloseProc(&hProcess);

	return alloc;
}
#else
LM_PRIVATE lm_address_t
_LM_AllocMemoryEx(lm_process_t *pproc,
		  lm_size_t     size,
		  lm_prot_t     prot)
{
	_lm_syscall_data_t data;
	lm_uintptr_t       syscall_ret = (lm_uintptr_t)MAP_FAILED;

#	if LM_OS == LM_OS_LINUX
	if (pproc->bits == 64)
		data.syscall_num = SYS_mmap;
	else
		data.syscall_num = SYS_mmap2;
#	else
	data.syscall_num = SYS_mmap;
#	endif

	data.arg0 = 0; /* addr */
	data.arg1 = (lm_uintptr_t)size; /* length */
	data.arg2 = (lm_uintptr_t)_LM_GetRealProt(prot); /* prot */
	data.arg3 = (lm_uintptr_t)(MAP_PRIVATE | MAP_ANON); /* flags */
	data.arg4 = (lm_uintptr_t)-1; /* fd */
	data.arg5 = (lm_uintptr_t)0; /* offset */

	if (!_LM_SystemCallEx(pproc, &data, &syscall_ret))
		return LM_ADDRESS_BAD;

	if (syscall_ret == (lm_uintptr_t)MAP_FAILED)
		return LM_ADDRESS_BAD;

	return (lm_address_t)syscall_ret;
}
#endif

LM_API lm_address_t
LM_AllocMemoryEx(lm_process_t *pproc,
		 lm_size_t     size,
		 lm_prot_t     prot)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || size == 0 || !LM_VALID_PROT(prot))
		return LM_ADDRESS_BAD;

	return _LM_AllocMemoryEx(pproc, size, prot);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_FreeMemory(lm_address_t alloc,
	       lm_size_t    size)
{
	return VirtualFree(alloc, 0, MEM_RELEASE) ? LM_TRUE : LM_FALSE;
}
#else
LM_PRIVATE lm_bool_t
_LM_FreeMemory(lm_address_t alloc,
	       lm_size_t    size)
{
	return munmap((void *)alloc, size) ? LM_FALSE : LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size)
{
	/* size can be 0 (at least on Windows, where it MUST be 0) */
	if (alloc == LM_ADDRESS_BAD)
		return LM_FALSE;

	return _LM_FreeMemory(alloc, size);	
}
/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_FreeMemoryEx(lm_process_t *pproc,
		 lm_address_t  alloc,
		 lm_size_t     size)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hProcess;
	if (!_LM_OpenProc(pproc->pid, &hProcess))
		return ret;

	ret = VirtualFreeEx(hProcess, alloc, 0, MEM_RELEASE) ?
		LM_TRUE : LM_FALSE;

	_LM_CloseProc(&hProcess);

	return ret;
}
#else
LM_PRIVATE lm_bool_t
_LM_FreeMemoryEx(lm_process_t *pproc,
		 lm_address_t  alloc,
		 lm_size_t     size)
{
	_lm_syscall_data_t data;
#	if LM_OS == LM_OS_LINUX
	data.syscall_num = __NR_munmap;
#	else
	data.syscall_num = SYS_mmap;
#	endif

	data.arg0 = (lm_uintptr_t)alloc;
	data.arg1 = (lm_uintptr_t)size;
	data.arg2 = data.arg3 = data.arg4 = data.arg5 = 0;

	return _LM_SystemCallEx(pproc, &data, LM_NULLPTR);
}
#endif

LM_API lm_bool_t
LM_FreeMemoryEx(lm_process_t *pproc,
		lm_address_t  alloc,
		lm_size_t     size)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || alloc == LM_ADDRESS_BAD)
		return LM_FALSE;

	return _LM_FreeMemoryEx(pproc, alloc, size);
}

