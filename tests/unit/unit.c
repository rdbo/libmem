#include <libmem/libmem.h>
#include "minunit.h"
#include <stdio.h>
#include <stdlib.h>

#if LM_OS == LM_OS_WIN
#	define TARGET_PROC "target.exe"
#else
#	define TARGET_PROC "target"
#endif

#define UNIT_TEST(func) { \
	extern char *test_##func(); \
	char *result; \
	printf("%s... ", #func); \
	fflush(stdout); \
	result = test_##func(); \
	if (result) { \
		printf("ERROR: %s\n", result); \
		exit(1); \
	} \
	printf("OK\n"); \
}

void test_process()
{
	UNIT_TEST(LM_EnumProcesses);
	UNIT_TEST(LM_GetProcess);
	UNIT_TEST(LM_GetProcessEx);
	UNIT_TEST(LM_FindProcess);
	UNIT_TEST(LM_IsProcessAlive);
	UNIT_TEST(LM_GetSystemBits);
}

void test_thread()
{
	UNIT_TEST(LM_GetThread);
	UNIT_TEST(LM_EnumThreads);
	UNIT_TEST(LM_GetThreadEx);
	UNIT_TEST(LM_EnumThreadsEx);
	UNIT_TEST(LM_GetThreadProcess);
}

void test_module()
{
	UNIT_TEST(LM_EnumModules);
	UNIT_TEST(LM_EnumModulesEx);
	UNIT_TEST(LM_FindModule);
	UNIT_TEST(LM_FindModuleEx);
	UNIT_TEST(LM_LoadModule);
	UNIT_TEST(LM_UnloadModule);
	UNIT_TEST(LM_LoadModuleEx);
}

lm_process_t current_process;
lm_process_t target_process;

int main()
{
	printf("[*] Unit Tests\n");
	printf("[*] NOTE: Some operations may require root access (or Administrator)\n");

	test_process();
	printf("[*] Searching for target process...\n");

	if (!LM_GetProcess(&current_process)) {
		printf("[!] Failed to retrieve current process\n");
		exit(1);
	}
	
	if (!LM_FindProcess(TARGET_PROC, &target_process)) {
		printf("[!] Target process not found: make sure '%s' is running\n", TARGET_PROC);
		exit(1);
	}
	
	test_thread();
	test_module();

	return 0;
}