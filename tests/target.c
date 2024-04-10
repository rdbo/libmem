#include <libmem/libmem.h>
#include <stdio.h>

#ifdef _WIN32
#	include <windows.h>
#	define do_sleep() Sleep(1000)
#else
#	include <unistd.h>
#	include <dlfcn.h>
#	define do_sleep() sleep(1)
#endif

LM_API_EXPORT void
hk_wait_message()
{
	printf("*");
	fflush(stdout);
}

LM_API_EXPORT void
wait_message()
{
	printf(".");
	fflush(stdout);
}

LM_API_EXPORT
int main()
{
	printf("[*] Target Process\n");
	printf("wait_message address: %p\n", (void *)wait_message);
	printf("hk_wait_message address: %p\n", (void *)hk_wait_message);
#	ifndef _WIN32
	printf("dlopen address: %p\n", (void *)dlopen);
#	endif
	printf("Waiting...");
	for (;;) {
		wait_message();
		do_sleep();
	}
	return 0;
}
