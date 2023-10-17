#include <libmem/libmem.h>
#include <stdio.h>

#if LM_OS == LM_OS_WIN
#	include <windows.h>
#	define do_sleep() Sleep(1000)
#else
#	include <unistd.h>
#	define do_sleep() sleep(1)
#endif

void wait_message()
{
	printf("Waiting...\n");
}

int main()
{
	for (;;) {
		wait_message();
		do_sleep();
	}
	return 0;
}