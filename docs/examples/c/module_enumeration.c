#include <libmem/libmem.h>

lm_bool_t
EnumModulesCallback(lm_module_t *pmod,
		    lm_void_t   *arg)
{
	printf("[*] Module Base: %p\n", (void *)pmod->base);
	printf("[*] Module End:  %p\n", (void *)pmod->end);
	printf("[*] Module Size: %p\n", (void *)pmod->size);
	printf("[*] Module Name: %s\n", pmod->name);
	printf("[*] Module Path: %s\n", pmod->path);
	printf("====================\n");

	return LM_TRUE;
}

int
main()
{
	LM_EnumModules(EnumModulesCallback, LM_NULL);

	return 0;
}
