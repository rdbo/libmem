#include "internal.h"
#if LM_OS != LM_OS_WIN
#	include <sys/uio.h>
#endif

LM_API lm_size_t
LM_ReadMemory(lm_address_t src,
	      lm_byte_t   *dst,
	      lm_size_t    size)
{
	lm_size_t i;

	LM_ASSERT(src != LM_ADDRESS_BAD && dst != LM_NULLPTR && size > 0);

	for (i = 0; i < size; ++i)
		dst[i] = ((lm_byte_t *)src)[i];

	return i;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_ReadMemoryEx(lm_process_t proc,
		 lm_address_t src,
		 lm_byte_t   *dst,
		 lm_size_t    size)
{
	return (lm_size_t)ReadProcessMemory(proc.handle, src, dst, size, NULL);
}
#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
LM_PRIVATE lm_size_t
_LM_ReadMemoryEx(lm_process_t proc,
		 lm_address_t src,
		 lm_byte_t   *dst,
		 lm_size_t    size)
{
	struct iovec iosrc = { 0 };
	struct iovec iodst = { 0 };
	ssize_t rdsize;

	iodst.iov_base = dst;
	iodst.iov_len  = size;
	iosrc.iov_base = src;
	iosrc.iov_len  = size;
	rdsize = (lm_size_t)process_vm_readv(proc.pid, &iodst, 1,
					     &iosrc, 1, 0);

	if (rdsize == -1)
		return 0;

	return (lm_size_t)rdsize;
}
#else
LM_PRIVATE lm_size_t
_LM_ReadMemoryEx(lm_process_t proc,
		 lm_address_t src,
		 lm_byte_t   *dst,
		 lm_size_t    size)
{
	int fd;
	lm_tchar_t mem_path[LM_PATH_MAX] = { 0 };
	ssize_t rdsize;

	LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path),
		    LM_STR("%s/%d/mem"), LM_PROCFS, proc.pid);

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
LM_ReadMemoryEx(lm_process_t proc,
		lm_address_t src,
		lm_byte_t   *dst,
		lm_size_t    size)
{
	LM_ASSERT(_LM_ValidProcess(proc) &&
		  src != LM_ADDRESS_BAD &&
		  dst != LM_NULLPTR &&
		  size > 0);

	return _LM_ReadMemoryEx(proc, src, dst, size);
}

/********************************/

LM_API lm_size_t
LM_WriteMemory(lm_address_t dst,
	       lm_bstring_t src,
	       lm_size_t    size)
{
	lm_size_t i;

	LM_ASSERT(dst != LM_ADDRESS_BAD && src != LM_NULLPTR && size > 0);

	for (i = 0; i < size; ++i)
		((lm_byte_t *)dst)[i] = src[i];

	return i;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_size_t
_LM_WriteMemoryEx(lm_process_t proc,
		  lm_address_t dst,
		  lm_bstring_t src,
		  lm_size_t    size)
{
	return (lm_size_t)WriteProcessMemory(proc.handle, dst, src,
					     size, NULL);
}
#elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
LM_PRIVATE lm_size_t
_LM_WriteMemoryEx(lm_process_t proc,
		  lm_address_t dst,
		  lm_bstring_t src,
		  lm_size_t    size)
{
	struct iovec iosrc = { 0 };
	struct iovec iodst = { 0 };
	ssize_t wrsize;

	iosrc.iov_base = src;
	iosrc.iov_len = size;
	iodst.iov_base = dst;
	iodst.iov_len = size;
	wrsize = process_vm_writev(proc.pid, &iosrc, 1, &iodst, 1, 0);

	if (wrsize == -1)
		return 0;

	return (lm_size_t)wrsize;
}
#else
LM_PRIVATE lm_size_t
_LM_WriteMemoryEx(lm_process_t proc,
		  lm_address_t dst,
		  lm_bstring_t src,
		  lm_size_t    size)
{
	int fd;
	lm_tchar_t mem_path[LM_PATH_MAX] = { 0 };
	ssize_t wrsize;

	LM_SNPRINTF(mem_path, LM_ARRLEN(mem_path),
		    LM_STR("%s/%d/mem"), LM_PROCFS, proc.pid);

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
LM_WriteMemoryEx(lm_process_t proc,
		 lm_address_t dst,
		 lm_bstring_t src,
		 lm_size_t    size)
{
	LM_ASSERT(_LM_ValidProcess(proc) &&
		  dst != LM_ADDRESS_BAD &&
		  src != LM_NULLPTR &&
		  size > 0);

	return _LM_WriteMemoryEx(proc, dst, src, size);
}

/********************************/

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

/********************************/

LM_API lm_size_t
LM_SetMemoryEx(lm_process_t proc,
	       lm_address_t dst,
	       lm_byte_t    byte,
	       lm_size_t    size)
{
	lm_size_t  wrsize = 0;
	lm_byte_t *data;

	data = (lm_byte_t *)LM_MALLOC(size);
	if (!data)
		return wrsize;

	if (LM_SetMemory(data, byte, size) != size)
		return wrsize;
	
	wrsize = LM_WriteMemoryEx(proc, dst, data, size);

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

	if (!VirtualProtect(addr, size, prot, &old_prot))
		return LM_FALSE

	if (oldprot)
		*oldprot = (lm_prot_t)old_prot;

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

	if (mprotect(addr, size, prot))
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
	LM_ASSERT(addr != LM_ADDRESS_BAD && size > 0);
	
	return _LM_ProtMemory(addr, size, prot, oldprot);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_ProtMemoryEx(lm_process_t proc,
		 lm_address_t addr,
		 lm_size_t    size,
		 lm_prot_t    prot,
		 lm_prot_t   *oldprot)
{
	DWORD old_prot;
	if (!VirtualProtectEx(proc.handle, addr, size, prot, &old_prot))
		return LM_FALSE;

	if (oldprot)
		*oldprot = (lm_prot_t)old_prot;

	return LM_TRUE;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_bool_t
_LM_ProtMemoryEx(lm_process_t proc,
		 lm_address_t addr,
		 lm_size_t    size,
		 lm_prot_t    prot,
		 lm_prot_t   *oldprot)
{
	/* TODO: Reimplement */

	return LM_FALSE;
}
#else
LM_PRIVATE lm_bool_t
_LM_ProtMemoryEx(lm_process_t proc,
		 lm_address_t addr,
		 lm_size_t    size,
		 lm_prot_t    prot,
		 lm_prot_t   *oldprot)
{
	/* TODO: Reimplement */

	return LM_FALSE;
}
#endif

LM_API lm_bool_t
LM_ProtMemoryEx(lm_process_t proc,
		lm_address_t addr,
		lm_size_t    size,
		lm_prot_t    prot,
		lm_prot_t   *oldprot)
{
	LM_ASSERT(_LM_ValidProcess(proc) &&
		  addr != LM_ADDRESS_BAD &&
		  size > 0);

	return _LM_ProtMemoryEx(proc, addr, size, prot, oldprot);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_address_t
_LM_AllocMemory(lm_size_t size,
		lm_prot_t prot)
{
	lm_address_t alloc;

	alloc = (lm_address_t)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, prot);
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
		mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANON, -1, 0)
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
	LM_ASSERT(size > 0);

	return _LM_AllocMemory(size, prot);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_address_t
_LM_AllocMemoryEx(lm_process_t proc,
		  lm_size_t    size,
		  lm_prot_t    prot)
{
	lm_address_t alloc;

	alloc = (lm_address_t)VirtualAllocEx(proc.handle, NULL, size,
					     MEM_COMMIT | MEM_RESERVE, prot);
	if (!alloc)
		alloc = LM_ADDRESS_BAD;

	return alloc;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_address_t
_LM_AllocMemoryEx(lm_process_t proc,
		  lm_size_t    size,
		  lm_prot_t    prot)
{
	/* TODO: Reimplement */

	return LM_ADDRESS_BAD;
}
#else
LM_PRIVATE lm_address_t
_LM_AllocMemoryEx(lm_process_t proc,
		  lm_size_t    size,
		  lm_prot_t    prot)
{
	/* TODO: Reimplement */

	return LM_ADDRESS_BAD;
}
#endif

LM_API lm_address_t
LM_AllocMemoryEx(lm_process_t proc,
		 lm_size_t    size,
		 lm_prot_t    prot)
{
	LM_ASSERT(_LM_ValidProcess(proc) && size > 0);

	return _LM_AllocMemoryEx(proc, size, prot);
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
	return munmap(alloc, size) ? LM_FALSE : LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size)
{
	/* size can be 0 (at least on Windows, where it MUST be 0) */
	LM_ASSERT(alloc != LM_ADDRESS_BAD);
	
	return _LM_FreeMemory(alloc, size);	
}
/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_FreeMemoryEx(lm_process_t proc,
		 lm_address_t alloc,
		 lm_size_t    size)
{
	return VirtualFreeEx(proc.handle, alloc, 0, MEM_RELEASE) ?
		LM_TRUE : LM_FALSE;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_bool_t
_LM_FreeMemoryEx(lm_process_t proc,
		 lm_address_t alloc,
		 lm_size_t    size)
{
	/* TODO: Reimplement */

	return LM_FALSE;
}
#else
LM_PRIVATE lm_bool_t
_LM_FreeMemoryEx(lm_process_t proc,
		 lm_address_t alloc,
		 lm_size_t    size)
{
	/* TODO: Reimplement */

	return LM_FALSE;
}
#endif

LM_API lm_bool_t
LM_FreeMemoryEx(lm_process_t proc,
		lm_address_t alloc,
		lm_size_t    size)
{
	LM_ASSERT(_LM_ValidProcess(proc) && alloc != LM_ADDRESS_BAD);

	return _LM_FreeMemoryEx(proc, alloc, size);
}

