#include "internal.h"

typedef struct {
	lm_pid_t pid;
	lm_bool_t (LM_CALL *callback)(lm_thread_t *pthr, lm_void_t *arg);
	lm_void_t *arg;
} _lm_enum_tids_t;

LM_PRIVATE lm_bool_t LM_CALL
_LM_EnumThreadsExCallback(const lm_process_t *pproc,
			  lm_void_t          *arg)
{
	_lm_enum_tids_t *data = (_lm_enum_tids_t *)arg;
	lm_thread_t thread;
	/* if the given pid owns the current pid, it is its thread or it's the target process */
	/* NOTE: this could be optimized by just calling the callback with the PID right away */
	if (pproc->ppid == data->pid || pproc->pid == data->pid) {
		thread.tid = (lm_tid_t)pproc->pid;
		if (!data->callback(&thread, data->arg))
			return LM_FALSE;
	}
	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumThreadsEx(const lm_process_t *pproc,
		  lm_bool_t (LM_CALL *callback)(lm_thread_t *pthr,
						lm_void_t   *arg),
		  lm_void_t          *arg)
{
	_lm_enum_tids_t data;
	data.pid = pproc->pid;
	data.callback = callback;
	data.arg = arg;
	return LM_EnumProcesses(_LM_EnumThreadsExCallback, (lm_void_t *)&data);
}
