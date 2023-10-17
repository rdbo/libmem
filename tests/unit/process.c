#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

const int ENUM_PROCS_CBNUM = 1234;

struct enum_procs_cb {
	int number;
	lm_bool_t check;
};

lm_bool_t _LM_EnumProcessesCallback(lm_process_t *proc, lm_void_t *arg)
{
	struct enum_procs_cb *cbarg = (struct enum_procs_cb *)arg;
	if (cbarg->number == ENUM_PROCS_CBNUM && CHECK_PROCESS(proc)) {
		cbarg->check = LM_TRUE;
	}

	return LM_FALSE;
}

char *test_LM_EnumProcesses()
{
	struct enum_procs_cb cbarg;
	cbarg.number = ENUM_PROCS_CBNUM;
	cbarg.check = LM_FALSE;

	mu_assert("failed to enumerate processes", LM_EnumProcesses(_LM_EnumProcessesCallback, (lm_void_t *)&cbarg) == LM_TRUE);
	mu_assert("cbarg.check is not LM_TRUE", cbarg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments", LM_EnumProcesses(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetProcess()
{
	lm_process_t proc;
	mu_assert("failed to retrieve current process", LM_GetProcess(&proc) == LM_TRUE);
	mu_assert("process is not valid", CHECK_PROCESS(&proc));
	mu_assert("function attempted to run with bad arguments", LM_GetProcess(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetProcessEx()
{
	lm_process_t curproc;
	lm_process_t proc;

	mu_assert("failed to retrieve current process", LM_GetProcess(&curproc) == LM_TRUE);
	mu_assert("current process is invalid", CHECK_PROCESS(&curproc));
	mu_assert("failed to retrieve current process from pid", LM_GetProcessEx(curproc.pid, &proc));
	mu_assert("retrieved process is invalid", CHECK_PROCESS(&proc));
	mu_assert("processes don't match", EQUAL_PROCESSES(&curproc, &proc));
	mu_assert("function attempted to run with bad arguments (invalid procbuf)", LM_GetProcessEx(curproc.pid, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid pid)", LM_GetProcessEx(LM_PID_BAD, &proc) == LM_FALSE);

	return NULL;
}

char *test_LM_FindProcess()
{
	lm_process_t curproc;
	lm_process_t proc;

	mu_assert("failed to retrieve current process", LM_GetProcess(&curproc) == LM_TRUE);
	mu_assert("current process is invalid", CHECK_PROCESS(&curproc));
	mu_assert("failed to find current process from string", LM_FindProcess(curproc.name, &proc));
	mu_assert("retrieved process is invalid", CHECK_PROCESS(&proc));
	mu_assert("processes don't match", EQUAL_PROCESSES(&curproc, &proc));
	mu_assert("function attempted to run with bad arguments (invalid procstr)", LM_FindProcess(LM_NULLPTR, &proc) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid procbuf)", LM_FindProcess(curproc.name, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_IsProcessAlive()
{
	lm_process_t curproc;

	mu_assert("failed to retrieve current process", LM_GetProcess(&curproc) == LM_TRUE);
	mu_assert("current process is invalid", CHECK_PROCESS(&curproc));
	mu_assert("process is alive", LM_IsProcessAlive(&curproc) == LM_TRUE);
	curproc.pid = LM_PID_BAD;
	mu_assert("process does not exist", LM_IsProcessAlive(&curproc) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments", LM_IsProcessAlive(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetSystemBits()
{
	mu_assert("wrong system bits", LM_GetSystemBits() == sizeof(uintmax_t) * 8);
	return NULL;
}