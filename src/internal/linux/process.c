#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *pproc,
						lm_void_t    *arg),
		  lm_void_t          *arg)
{
	lm_bool_t ret = LM_FALSE;
	struct dirent *pdirent;
	DIR *dir;
	lm_process_t proc;

	dir = opendir(LM_PROCFS);

	if (!dir)
		return ret;
		
	while ((pdirent = readdir(dir))) {
		proc.pid = (lm_pid_t)LM_ATOI(pdirent->d_name);

		/* check if 'atoi' failed */
		if (!proc.pid && LM_STRCMP(pdirent->d_name, LM_STR("0")))
			continue;

		proc.ppid = _LM_GetParentIdEx(proc.pid);
		if (!_LM_GetProcessPathEx(proc.pid, proc.path, LM_ARRLEN(proc.path)))
			continue;

		if (!_LM_GetNameFromPath(proc.path, proc.name, LM_ARRLEN(proc.name)))
			continue;

		proc.start_time = _LM_GetProcessStartTime(proc.pid);
		if (proc.start_time == LM_TIME_BAD)
			continue;

		proc.bits = _LM_GetProcessBitsEx(proc.path);

		if (callback(&proc, arg) == LM_FALSE)
			break;
	}

	ret = LM_TRUE;
		
	closedir(dir);
	return ret;
}
