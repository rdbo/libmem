#include "minunit.h"
#include <stdio.h>
#include <stdlib.h>

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
}

int main()
{
	printf("[*] Unit Tests\n");

	test_process();

	return 0;
}