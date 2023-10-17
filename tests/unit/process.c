#include <libmem/libmem.h>
#include "unit.h"
#include "minunit.h"

const int ENUM_PROCS_CBNUM = 1234;

struct enum_procs_cb {
	int number;
	lm_bool_t check;
};

lm_bool_t _LM_EnumProcessesCallback(lm_process_t *proc, lm_void_t *arg)
{
	struct enum_procs_cb *cbarg = (struct enum_procs_cb *)arg;
	if (cbarg->number == ENUM_PROCS_CBNUM && proc->pid != LM_PID_BAD) {
		cbarg->check = LM_TRUE;
	}

	return LM_FALSE;
}

char *test_LM_EnumProcesses()
{
	struct enum_procs_cb cbarg;
	cbarg.number = ENUM_PROCS_CBNUM;
	cbarg.check = LM_FALSE;

	mu_assert("function returned LM_FALSE on valid call", LM_EnumProcesses(_LM_EnumProcessesCallback, (lm_void_t *)&cbarg) == LM_TRUE);
	mu_assert("cbarg.check is not LM_TRUE", cbarg.check == LM_TRUE);
	mu_assert("function attempted to run with bad parameters", LM_EnumProcesses(LM_NULL, LM_NULL) == LM_FALSE);

	return NULL;
}