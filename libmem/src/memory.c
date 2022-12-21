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

/********************************/

/********************************/
