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

lm_process_t target_process;

int main()
{
	printf("[*] Unit Tests\n");

	test_process();
	printf("[*] Searching for target process...\n");
	if (!LM_FindProcess(TARGET_PROC, &target_process)) {
		printf("[!] Target process not found: make sure '%s' is running\n", TARGET_PROC);
		exit(1);
	}
	test_thread();

	return 0;
}