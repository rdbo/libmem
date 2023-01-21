#include <libmem/libmem.h>

lm_bool_t
EnumProcessesCallback(lm_process_t *pproc,
		      lm_void_t    *arg)
{
	printf("[*] Process PID:  %u\n", pproc->pid);
	printf("[*] Process PPID: %u\n", pproc->ppid);
	printf("[*] Process Name: %s\n", pproc->name);
	printf("[*] Process Path: %s\n", pproc->path);
	printf("[*] Process Bits: %zu\n", pproc->bits);
	printf("====================\n");

	return LM_TRUE;
}

int
main()
{
	LM_EnumProcesses(EnumProcessesCallback, LM_NULL);

	return 0;
}
