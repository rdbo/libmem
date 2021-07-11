#include <libmem.h>

lm_bool_t
EnumProcessesCallback(lm_pid_t   pid,
		      lm_void_t *arg)
{
	lm_process_t proc;
	lm_tchar_t   path[LM_PATH_MAX] = { 0 };
	lm_tchar_t   name[64] = { 0 };
	lm_size_t    bits;

	LM_OpenProcessEx(pid, &proc);

	LM_GetProcessPathEx(proc, path, LM_ARRLEN(path));
	LM_GetProcessNameEx(proc, name, LM_ARRLEN(name));
	bits = LM_GetProcessBitsEx(proc);

	printf("[*] PID:  %d\n",  proc.pid);
	printf("[*] Path: %s\n",  path);
	printf("[*] Name: %s\n",  name);
	printf("[*] Bits: %lu\n", bits);
	printf("====================\n");

	LM_CloseProcess(&proc);

	if (pid == LM_GetProcessId()) {
		*(lm_pid_t *)arg = pid;
		return LM_FALSE;
	}

	return LM_TRUE;
}

lm_bool_t
EnumModulesCallback(lm_module_t  mod,
		    lm_tstring_t path,
		    lm_void_t   *arg)
{
	printf("[*] Module Path: %s\n", path);
	printf("[*] Module Base: %p\n", mod.base);
	printf("[*] Module Size: %p\n", (lm_void_t *)mod.size);
	printf("[*] Module End:  %p\n", mod.end);
	printf("====================\n");

	return LM_TRUE;
}

int
main()
{
	lm_pid_t pid;
	lm_process_t proc;

	printf("[+] Tests Started\n");

	LM_EnumProcesses(EnumProcessesCallback, (lm_void_t *)&pid);
	LM_OpenProcessEx(pid, &proc);
	LM_EnumModulesEx(proc, EnumModulesCallback, (lm_void_t *)LM_NULL);
	LM_CloseProcess(&proc);

	printf("[-] Tests Ended\n");
	getchar();

	return 0;
}
