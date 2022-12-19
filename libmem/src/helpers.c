#if LM_OS != LM_OS_WIN
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
		filebuf = (lm_tchar_t *)LM_CALLOC(total + 2, sizeof(c));
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

