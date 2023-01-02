#include <libmem/libmem.h>

#if LM_CHARSET == LM_CHARSET_UC
#define LM_PRINTF wprintf
#else
#define LM_PRINTF printf
#endif

#define LOAD_STR LM_STR("[*] Libtest Loaded!\n")
#define UNLOAD_STR LM_STR("[*] Libtest Unloaded!\n")

#if LM_OS == LM_OS_WIN
BOOL APIENTRY
DllMain(HMODULE hModule,
	DWORD   dwReason,
	LPVOID  lpReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		LM_PRINTF(LOAD_STR);	
		break;
	case DLL_PROCESS_DETACH:
		LM_PRINTF(UNLOAD_STR);
		break;
	}
	return TRUE;
}
#else
void __attribute__((constructor))
libentry(void)
{
	LM_PRINTF(LOAD_STR);
}

void __attribute__((destructor))
libexit(void)
{
	LM_PRINTF(UNLOAD_STR);
}
#endif
