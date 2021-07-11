#include <libmem.h>

lm_bool_t
EnumProcessesCallback(lm_pid_t   pid,
		      lm_void_t *arg)
{
	printf("[*] PID: %d\n", pid);
	return LM_TRUE;
}

int
main()
{
	LM_EnumProcesses(EnumProcessesCallback, (lm_void_t *)LM_NULL);
	return 0;
}
