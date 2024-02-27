#include <libmem/libmem.h>
#include <stdio.h>

#ifdef _WIN32
#	include <windows.h>
#	define do_sleep() Sleep(1000)
#else
#	include <unistd.h>
#	define do_sleep() sleep(1)
#endif

void wait_message()
{
	printf(".");
	fflush(stdout);
}

int main()
{
	printf("[*] Target Process\n");
	printf("Waiting...");
	for (;;) {
		wait_message();
		do_sleep();
	}
	return 0;
}
