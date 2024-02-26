#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_GetThread(lm_thread_t *thrbuf)
{
	/* the process id and the thread id are the same (threads are also processes) */
	thrbuf->tid = (lm_tid_t)getpid();
	return LM_TRUE;
}

/********************************/

LM_PRIVATE lm_pid_t
_LM_GetPidFromThread(const lm_thread_t *pthr)
{
	return (lm_pid_t)pthr->tid;
}
