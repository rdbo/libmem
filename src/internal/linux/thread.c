#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(const lm_process_t *pproc,
		  lm_bool_t (LM_CALL *callback)(lm_thread_t *pthr,
						lm_void_t   *arg),
		  lm_void_t          *arg)
{
	DIR *pdir;
	struct dirent *pdirent;
	lm_char_t task_path[LM_PATH_MAX] = { 0 };
	lm_thread_t thread;

	LM_SNPRINTF(task_path, LM_ARRLEN(task_path),
		    LM_STR("/proc/%d/task"), pproc->pid);

	pdir = opendir(task_path);
	if (!pdir)
		return LM_FALSE;
		
	while ((pdirent = readdir(pdir))) {
		thread.tid = LM_ATOI(pdirent->d_name);

		if (!thread.tid && LM_STRCMP(pdirent->d_name, "0"))
			continue;

		if (!callback(&thread, arg))
			break;
	}

	closedir(pdir);

	return LM_TRUE;
}
