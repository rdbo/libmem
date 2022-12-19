#if LM_OS != LM_OS_WIN
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
	
	while ((rdsize = read(fd, buf, sizeof(buf))) > 0) {
		/* Use 'realloc' to increase the buffer size and copy the old data */
		filebuf = (lm_tchar_t *)LM_REALLOC(filebuf, total + rdsize + sizeof(lm_tchar_t));

		if (!filebuf) {
			total = 0;
			break;
		}
		
		LM_MEMCPY(&filebuf[total], buf, rdsize);
		total += rdsize;
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

/* TODO: Receive a pointer instead of a copy of proc */
static lm_bool_t
_LM_ValidProcess(lm_process_t proc)
{
	lm_bool_t ret = LM_FALSE;

	if (proc.pid == (lm_pid_t)LM_BAD)
		return ret;

#	if LM_OS == LM_OS_WIN
	{
		if (proc.pid != LM_GetProcessId() && !proc.handle)
			return ret;
	}
#	elif LM_OS == LM_OS_LINUX || LM_OS == LM_OS_BSD || LM_OS == LM_OS_ANDROID
	{
		
	}
#	endif

	ret = LM_TRUE;

	return ret;
}

