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
	mu_assert("failed to retrieve current process", LM_GetProcess(&current_process) == LM_TRUE);
	mu_assert("process is not valid", CHECK_PROCESS(&current_process));
	mu_assert("function attempted to run with bad arguments", LM_GetProcess(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetProcessEx()
{
	lm_process_t proc;

	mu_assert("failed to retrieve current process from pid", LM_GetProcessEx(current_process.pid, &proc));
	mu_assert("retrieved process is invalid", CHECK_PROCESS(&proc));
	mu_assert("processes don't match", EQUAL_PROCESSES(&current_process, &proc));
	mu_assert("function attempted to run with bad arguments (invalid procbuf)", LM_GetProcessEx(current_process.pid, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid pid)", LM_GetProcessEx(LM_PID_BAD, &proc) == LM_FALSE);

	return NULL;
}

char *test_LM_FindProcess()
{
	mu_assert("failed to find target process from string", LM_FindProcess(TARGET_PROC, &target_process));
	mu_assert("retrieved process is invalid", CHECK_PROCESS(&target_process));
	mu_assert("function attempted to run with bad arguments (invalid procstr)", LM_FindProcess(LM_NULLPTR, &target_process) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid procbuf)", LM_FindProcess(TARGET_PROC, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_IsProcessAlive()
{
	lm_process_t bad_process;
	bad_process.pid = LM_PID_BAD;
	
	mu_assert("process is alive, function returned LM_FALSE", LM_IsProcessAlive(&current_process) == LM_TRUE);
	mu_assert("process does not exist", LM_IsProcessAlive(&bad_process) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments", LM_IsProcessAlive(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetSystemBits()
{
	mu_assert("wrong system bits", LM_GetSystemBits() == sizeof(uintmax_t) * 8);
	return NULL;
}