#include <libmem.h>
#include <stdio.h>

#if LM_CHARSET == LM_CHARSET_UC
#define LM_PRINTF wprintf
#else
#define LM_PRINTF printf
#endif

int
main()
{
	lm_pid_t     pid;
	lm_process_t proc = { 0 };
	lm_module_t  mod = { 0 };
	lm_tchar_t  *procname;
	lm_tchar_t  *procpath;
	lm_size_t    procbits;
	lm_tchar_t  *modname;
	lm_tchar_t  *modpath;
	lm_page_t    page;
	int          myvar = 0;
	int          mybuf;
	lm_byte_t    scanbuf[] = { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
	lm_address_t datascan;

	LM_PRINTF(LM_STR("[+] Tests Started\n"));

	procname = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	procpath = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	modname  = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));
	modpath  = LM_CALLOC(LM_PATH_MAX, sizeof(lm_tchar_t));

	pid = LM_GetProcessIdEx(TARGET_NAME);
	LM_OpenProcessEx(pid, &proc);
	LM_GetProcessNameEx(proc, procname, LM_PATH_MAX);
	LM_GetProcessPathEx(proc, procpath, LM_PATH_MAX);
	procbits = LM_GetProcessBitsEx(proc);

	LM_PRINTF(LM_STR("[*] Process ID:   %d\n"), proc.pid);
	LM_PRINTF(LM_STR("[*] Process Name: %s\n"), procname);
	LM_PRINTF(LM_STR("[*] Process Path: %s\n"), procpath);
	LM_PRINTF(LM_STR("[*] Process Bits: %lu\n"), procbits);
	LM_PRINTF(LM_STR("====================\n"));

	LM_GetModuleEx(proc, procpath, &mod);
	LM_GetModuleNameEx(proc, mod, modname, LM_PATH_MAX);
	LM_GetModulePathEx(proc, mod, modpath, LM_PATH_MAX);

	LM_PRINTF(LM_STR("[*] Module Base: %p\n"), mod.base);
	LM_PRINTF(LM_STR("[*] Module Size: %p\n"), (lm_void_t *)mod.size);
	LM_PRINTF(LM_STR("[*] Module End:  %p\n"), mod.end);
	LM_PRINTF(LM_STR("[*] Module Name: %s\n"), modname);
	LM_PRINTF(LM_STR("[*] Module Path: %s\n"), modpath);
	LM_PRINTF(LM_STR("====================\n"));

	LM_GetPageEx(proc, mod.base, &page);
	LM_PRINTF(LM_STR("[*] Page Base:  %p\n"), page.base);
	LM_PRINTF(LM_STR("[*] Page Size:  %p\n"), (lm_void_t *)page.size);
	LM_PRINTF(LM_STR("[*] Page End:   %p\n"), page.end);
	LM_PRINTF(LM_STR("[*] Page Prot:  %d\n"), page.prot);
	LM_PRINTF(LM_STR("[*] Page Flags: %d\n"), page.flags);
	LM_PRINTF(LM_STR("====================\n"));

	mybuf = 1337;
	LM_WriteMemoryEx(proc, (lm_address_t)&myvar,
			 (lm_bstring_t)&mybuf, sizeof(mybuf));
	
	mybuf = 0;
	LM_ReadMemoryEx(proc, (lm_address_t)&myvar,
			(lm_byte_t *)&mybuf, sizeof(myvar));
	
	datascan = LM_DataScanEx(proc,
				 scanbuf,
				 sizeof(scanbuf),
				 (lm_address_t)&scanbuf[-10],
				 (lm_address_t)&scanbuf[10]);
	
	LM_PRINTF(LM_STR("[*] Written Value: %d\n"), myvar);
	LM_PRINTF(LM_STR("[*] Read Value:    %d\n"), mybuf);
	LM_PRINTF(LM_STR("[*] ScanBuf Addr:  %p\n"), (lm_void_t *)scanbuf);
	LM_PRINTF(LM_STR("[*] Data Scan:     %p\n"), datascan);
	LM_PRINTF(LM_STR("====================\n"));

	LM_CloseProcess(&proc);
	LM_FREE(procname);
	LM_FREE(procpath);
	LM_FREE(modname);
	LM_FREE(modpath);

	LM_PRINTF(LM_STR("[-] Tests Ended\n"));
	getchar();

	return 0;
}
