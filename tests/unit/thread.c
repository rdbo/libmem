#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

char *test_LM_GetThread()
{
	mu_assert("failed to get current thread", LM_GetThread(&current_thread) == LM_TRUE);
	mu_assert("retrieved thread is invalid", CHECK_THREAD(&current_thread));
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

char *test_LM_EnumThreads()
{
	struct enum_threads_cbarg arg;

	arg.thread = &current_thread;
	arg.check = LM_FALSE;

	mu_assert("failed to enumerate threads", LM_EnumThreads(_LM_EnumThreadsCallback, (lm_void_t *)&arg) == LM_TRUE);
	mu_assert("could not find current thread", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments", LM_EnumThreads(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetThreadEx()
{
	mu_assert("failed to get a thread from the target process", LM_GetThreadEx(&target_process, &target_thread) == LM_TRUE);
	mu_assert("retrieved thread is invalid", CHECK_THREAD(&target_thread));
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_GetThreadEx(LM_NULLPTR, &target_thread) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid thread)", LM_GetThreadEx(&target_process, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_EnumThreadsEx()
{
	struct enum_threads_cbarg arg;
	arg.thread = &target_thread;
	arg.check = LM_FALSE;

	mu_assert("failed to enumerate threads", LM_EnumThreadsEx(&target_process, _LM_EnumThreadsCallback, (lm_void_t *)&arg) == LM_TRUE);
	mu_assert("could not find retrieved thread", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_EnumThreadsEx(LM_NULLPTR, _LM_EnumThreadsCallback, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumThreadsEx(&target_process, LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetThreadProcess()
{
	lm_process_t proc;
	
	mu_assert("failed to get thread process", LM_GetThreadProcess(&current_thread, &proc) == LM_TRUE);
	mu_assert("retrieved process is invalid", CHECK_PROCESS(&proc));
	mu_assert("processes don't match", EQUAL_PROCESSES(&current_process, &proc));
	mu_assert("function attempted to run with bad arguments (invalid thread)", LM_GetThreadProcess(LM_NULLPTR, &proc) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_GetThreadProcess(&current_thread, LM_NULLPTR) == LM_FALSE);

	return NULL;
}