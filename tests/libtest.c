#include <libmem/libmem.h>

#define LOAD_STR " <LIBTEST LOADED> "
#define UNLOAD_STR " <LIBTEST UNLOADED> "

#if LM_OS == LM_OS_WIN
BOOL APIENTRY
DllMain(HMODULE hModule,
	DWORD   dwReason,
	LPVOID  lpReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		printf(LOAD_STR);
		fflush(stdout);
		break;
	case DLL_PROCESS_DETACH:
		printf(UNLOAD_STR);
		fflush(stdout);
		break;
	}
	return TRUE;
}
#else
void __attribute__((constructor))
libentry(void)
{
	printf(LOAD_STR);
	fflush(stdout);
}

void __attribute__((destructor))
libexit(void)
{
	printf(UNLOAD_STR);
	fflush(stdout);
}
#endif
