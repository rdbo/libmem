#include <libmem.h>

lm_bool_t
EnumProcessesCallback(lm_pid_t   pid,
		      lm_void_t *arg)
{
	lm_process_t proc;
	lm_tchar_t   path[LM_PATH_MAX];
	lm_tchar_t   name[64];

	LM_OpenProcessEx(pid, &proc);

	LM_GetProcessPathEx(proc, path, LM_ARRLEN(path));
	LM_GetProcessNameEx(proc, name, LM_ARRLEN(name));

	printf("[*] PID:  %d\n", proc.pid);
	printf("[*] Path: %s\n", path);
	printf("[*] Name: %s\n", name);
	printf("====================\n");

	LM_CloseProcess(&proc);

	return LM_TRUE;
}

int
main()
{
	LM_EnumProcesses(EnumProcessesCallback, (lm_void_t *)LM_NULL);
	return 0;
}
