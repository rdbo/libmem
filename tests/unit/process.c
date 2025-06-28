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

char *test_LM_EnumProcesses(void *arg)
{
	struct enum_procs_cb cbarg;
	cbarg.number = ENUM_PROCS_CBNUM;
	cbarg.check = LM_FALSE;

	mu_assert("failed to enumerate processes", LM_EnumProcesses(_LM_EnumProcessesCallback, (lm_void_t *)&cbarg) == LM_TRUE);
	mu_assert("cbarg.check is not LM_TRUE", cbarg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments", LM_EnumProcesses(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetProcess(lm_process_t *pcurproc)
{
	mu_assert("failed to retrieve current process", LM_GetProcess(pcurproc) == LM_TRUE);
	mu_assert("process is not valid", CHECK_PROCESS(pcurproc));
	mu_assert("function attempted to run with bad arguments", LM_GetProcess(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetProcessEx(lm_process_t *pcurproc)
{
	lm_process_t proc;

	mu_assert("failed to retrieve current process from pid", LM_GetProcessEx(pcurproc->pid, &proc));
	mu_assert("retrieved process is invalid", CHECK_PROCESS(&proc));
	mu_assert("processes don't match", EQUAL_PROCESSES(pcurproc, &proc));
	mu_assert("function attempted to run with bad arguments (invalid procbuf)", LM_GetProcessEx(pcurproc->pid, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid pid)", LM_GetProcessEx(LM_PID_BAD, &proc) == LM_FALSE);

	return NULL;
}

char *test_LM_GetCommandLine(lm_process_t *pcurproc)
{
	lm_char_t **cmdline;
	lm_char_t **args;

	printf("\r\nentered function\n\r");
	cmdline = LM_GetCommandLine(pcurproc);
	printf("\r\nran function\r\n");
	mu_assert("failed to retrieve command line for current process", cmdline != NULL);
	mu_assert("invalid first argument of command line", *cmdline != NULL);
	printf("<CMDLINE:");

	for (args = cmdline; *args != NULL; ++args)
		printf(" %s", *args);
	printf("> ");

	LM_FreeCommandLine(cmdline);

	return NULL;
}

char *test_LM_FindProcess(lm_process_t *ptargetproc)
{
	mu_assert("failed to find target process from string", LM_FindProcess(TARGET_NAME, ptargetproc));
	mu_assert("retrieved process is invalid", CHECK_PROCESS(ptargetproc));
	mu_assert("function attempted to run with bad arguments (invalid procstr)", LM_FindProcess(LM_NULLPTR, ptargetproc) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid procbuf)", LM_FindProcess(TARGET_NAME, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_IsProcessAlive(lm_process_t *pcurproc)
{
	lm_process_t bad_process;
	bad_process.pid = LM_PID_BAD;
	
	mu_assert("process is alive, function returned LM_FALSE", LM_IsProcessAlive(pcurproc) == LM_TRUE);
	mu_assert("process does not exist", LM_IsProcessAlive(&bad_process) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments", LM_IsProcessAlive(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetSystemBits()
{
	lm_size_t bits;

	bits = LM_GetSystemBits();

	printf(" <BITS: %zd> ", (size_t)bits);
	fflush(stdout);

	mu_assert("wrong system bits", bits == 32 || bits == 64);

	return NULL;
}
