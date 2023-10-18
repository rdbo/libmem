#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"
#include <stdio.h>
#include <stdlib.h>

#define UNIT_TEST_P(func, arg) { \
	extern char *test_##func(void *); \
	char *result; \
	printf("%s... ", #func); \
	fflush(stdout); \
	result = test_##func(arg); \
	if (result) { \
		printf("ERROR: %s\n", result); \
		exit(1); \
	} \
	printf("OK\n"); \
}

#define UNIT_TEST(func) UNIT_TEST_P(func, NULL)

void test_process(lm_process_t *pcurproc, lm_process_t *ptargetproc)
{
	UNIT_TEST(LM_EnumProcesses);
	UNIT_TEST_P(LM_GetProcess, pcurproc);
	UNIT_TEST_P(LM_GetProcessEx, pcurproc);
	UNIT_TEST_P(LM_FindProcess, ptargetproc);
	UNIT_TEST_P(LM_IsProcessAlive, pcurproc);
	UNIT_TEST(LM_GetSystemBits);
}

void test_thread(lm_process_t *pcurproc, lm_process_t *ptargetproc, lm_thread_t *pcurthread, lm_thread_t *ptargetthread)
{
	struct thread_args arg;
	arg.pcurproc = pcurproc;
	arg.ptargetproc = ptargetproc;
	arg.pcurthread = pcurthread;
	arg.ptargetthread = ptargetthread;
	
	UNIT_TEST_P(LM_GetThread, &arg);
	UNIT_TEST_P(LM_EnumThreads, &arg);
	UNIT_TEST_P(LM_GetThreadEx, &arg);
	UNIT_TEST_P(LM_EnumThreadsEx, &arg);
	UNIT_TEST_P(LM_GetThreadProcess, &arg);
}

void test_module(lm_process_t *pcurproc, lm_process_t *ptargetproc)
{
	lm_module_t mod;
	struct load_module_args arg;
	arg.ptargetproc = ptargetproc;
	arg.pmod = &mod;

	UNIT_TEST_P(LM_EnumModules, pcurproc);
	UNIT_TEST_P(LM_EnumModulesEx, ptargetproc);
	UNIT_TEST_P(LM_FindModule, pcurproc);
	UNIT_TEST_P(LM_FindModuleEx, ptargetproc);
	UNIT_TEST_P(LM_LoadModule, &mod);
	UNIT_TEST_P(LM_UnloadModule, &mod);
	UNIT_TEST_P(LM_LoadModuleEx, &arg);
}

int main()
{
	lm_process_t current_process;
	lm_process_t target_process;
	lm_thread_t  current_thread;
	lm_thread_t  target_thread;
	
	printf("[*] Unit Tests\n");
	printf("[*] NOTE: Some operations may require root access (or Administrator)\n");

	test_process(&current_process, &target_process);
	test_thread(&current_process, &target_process, &current_thread, &target_thread);
	test_module(&current_process, &target_process);

	return 0;
}