#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

char *test_LM_GetThread(struct thread_args *thrarg)
{
	lm_thread_t *pcurthread = thrarg->pcurthread;
	
	mu_assert("failed to get current thread", LM_GetThread(pcurthread) == LM_TRUE);
	mu_assert("retrieved thread is invalid", CHECK_THREAD(pcurthread));
	mu_assert("function attempted to run with bad arguments", LM_GetThread(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

struct enum_threads_cbarg {
	lm_thread_t *thread;
	lm_bool_t check;
};

lm_bool_t _LM_EnumThreadsCallback(lm_thread_t *thread, lm_void_t *arg)
{
	struct enum_threads_cbarg *cbarg = (struct enum_threads_cbarg *)arg;
	if (EQUAL_THREADS(thread, cbarg->thread)) {
		cbarg->check = LM_TRUE;
		return LM_FALSE;
	}

	return LM_TRUE;
}

char *test_LM_EnumThreads(struct thread_args *thrarg)
{
	struct enum_threads_cbarg arg;

	arg.thread = thrarg->pcurthread;
	arg.check = LM_FALSE;

	mu_assert("failed to enumerate threads", LM_EnumThreads(_LM_EnumThreadsCallback, (lm_void_t *)&arg) == LM_TRUE);
	mu_assert("could not find current thread", arg.check == LM_TRUE);
	mu_assert("thread owner_pid does not match the expected process id", arg.thread->owner_pid == thrarg->pcurproc->pid);
	mu_assert("function attempted to run with bad arguments", LM_EnumThreads(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetThreadEx(struct thread_args *thrarg)
{
	lm_process_t *ptargetproc = thrarg->ptargetproc;
	lm_thread_t *ptargetthread = thrarg->ptargetthread;
	
	mu_assert("failed to get a thread from the target process", LM_GetThreadEx(ptargetproc, ptargetthread) == LM_TRUE);
	mu_assert("retrieved thread is invalid", CHECK_THREAD(ptargetthread));
	mu_assert("thread owner_pid does not match the expected process id", ptargetthread->owner_pid == ptargetproc->pid);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_GetThreadEx(LM_NULLPTR, ptargetthread) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid thread)", LM_GetThreadEx(ptargetproc, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_EnumThreadsEx(struct thread_args *thrarg)
{
	struct enum_threads_cbarg arg;
	lm_process_t *ptargetproc = thrarg->ptargetproc;
	
	arg.thread = thrarg->ptargetthread;
	arg.check = LM_FALSE;

	mu_assert("failed to enumerate threads", LM_EnumThreadsEx(ptargetproc, _LM_EnumThreadsCallback, (lm_void_t *)&arg) == LM_TRUE);
	mu_assert("could not find retrieved thread", arg.check == LM_TRUE);
	mu_assert("thread owner_pid does not match the expected process id", arg.thread->owner_pid == ptargetproc->pid);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_EnumThreadsEx(LM_NULLPTR, _LM_EnumThreadsCallback, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumThreadsEx(ptargetproc, LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetThreadProcess(struct thread_args *thrarg)
{
	lm_process_t *pcurproc = thrarg->pcurproc;
	lm_thread_t *pcurthread = thrarg->pcurthread;
	lm_process_t proc;
	
	mu_assert("failed to get thread process", LM_GetThreadProcess(pcurthread, &proc) == LM_TRUE);
	mu_assert("retrieved process is invalid", CHECK_PROCESS(&proc));
	mu_assert("processes don't match", EQUAL_PROCESSES(pcurproc, &proc));
	mu_assert("function attempted to run with bad arguments (invalid thread)", LM_GetThreadProcess(LM_NULLPTR, &proc) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_GetThreadProcess(pcurthread, LM_NULLPTR) == LM_FALSE);

	return NULL;
}
