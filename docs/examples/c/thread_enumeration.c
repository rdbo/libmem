#include <libmem/libmem.h>

lm_bool_t
EnumThreadsCallback(lm_thread_t *pthr,
		    lm_void_t   *arg)
{
	printf("%u ", pthr->tid);

	return LM_TRUE;
}

int
main()
{
	printf("[*] Current Threads: [ ");
	LM_EnumThreads(EnumThreadsCallback, LM_NULL);
	printf("]\n");

	return 0;
}
