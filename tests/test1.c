#include <libmem.h>

#if LM_CHARSET == LM_CHARSET_UC
#define LM_PRINTF wprintf
#else
#define LM_PRINTF printf
#endif

int
main()
{
	lm_process_t proc;
	lm_tchar_t   procname[LM_PATH_MAX];
	lm_tchar_t   procpath[LM_PATH_MAX];
	lm_pid_t     ppid;
	lm_tid_t     tid;
	lm_size_t    bits;
	lm_module_t  mod;
	lm_tchar_t   modname[LM_PATH_MAX];
	lm_tchar_t   modpath[LM_PATH_MAX];
	lm_address_t main_sym;
	lm_module_t  libtest_mod;
	lm_tchar_t   libtest_modname[LM_PATH_MAX];
	lm_tchar_t   libtest_modpath[LM_PATH_MAX];
	lm_page_t    page;
	lm_uintptr_t val = 10;
	lm_uintptr_t rdbuf;
	lm_uintptr_t wrbuf = 1337;
	lm_byte_t    scanme[] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };
	lm_tchar_t   mask[] = LM_STR("xxxxxxxxxx");
	lm_tchar_t   signature[] = LM_STR("10 20 30 40 50 60 70 80 90 A0");
	lm_address_t data_scan;
	lm_address_t pattern_scan;
	lm_address_t sig_scan;
	lm_address_t alloc;
	lm_prot_t    alloc_prot;
	lm_prot_t    alloc_oldprot;

	LM_PRINTF(LM_STR("[+] Test 1\n"));

	LM_OpenProcess(&proc);
	LM_GetProcessName(procname, LM_ARRLEN(procname));
	LM_GetProcessPath(procpath, LM_ARRLEN(procpath));
	ppid = LM_GetParentId();
	tid  = LM_GetThreadId();
	bits = LM_GetProcessBits();

	LM_PRINTF(LM_STR("[*] Process Name: %s\n"), procname);
	LM_PRINTF(LM_STR("[*] Process Path: %s\n"), procpath);
	LM_PRINTF(LM_STR("[*] PID:  %d\n"), proc.pid);
	LM_PRINTF(LM_STR("[*] PPID: %d\n"), ppid);
	LM_PRINTF(LM_STR("[*] TID:  %d\n"), tid);
	LM_PRINTF(LM_STR("[*] Bits: %lu\n"), bits);
	LM_PRINTF(LM_STR("====================\n"));

	LM_GetModule(LM_MOD_BY_STR, procpath, &mod);
	LM_GetModule(LM_MOD_BY_ADDR, mod.base, &mod);
	LM_GetModuleName(mod, modname, LM_ARRLEN(modname));
	LM_GetModulePath(mod, modpath, LM_ARRLEN(modpath));
	main_sym = LM_GetSymbol(mod, "main");
	LM_PRINTF(LM_STR("[*] Module Name: %s\n"), modname);
	LM_PRINTF(LM_STR("[*] Module Path: %s\n"), modpath);
	LM_PRINTF(LM_STR("[*] Module Base: %p\n"), mod.base);
	LM_PRINTF(LM_STR("[*] Module Size: %p\n"), (void *)mod.size);
	LM_PRINTF(LM_STR("[*] Module End:  %p\n"), mod.end);
	LM_PRINTF(LM_STR("[*] Main Addr:   %p\n"), main_sym);
	LM_PRINTF(LM_STR("====================\n"));

	LM_LoadModule(LM_STR(LIBTEST_PATH), &libtest_mod);
	LM_GetModuleName(libtest_mod, libtest_modname, LM_ARRLEN(libtest_modname));
	LM_GetModulePath(libtest_mod, libtest_modpath, LM_ARRLEN(libtest_modpath));
	LM_UnloadModule(libtest_mod);
	LM_PRINTF(LM_STR("[*] Module Name: %s\n"), libtest_modname);
	LM_PRINTF(LM_STR("[*] Module Path: %s\n"), libtest_modpath);
	LM_PRINTF(LM_STR("[*] Module Base: %p\n"), libtest_mod.base);
	LM_PRINTF(LM_STR("[*] Module Size: %p\n"), (void *)libtest_mod.size);
	LM_PRINTF(LM_STR("[*] Module End:  %p\n"), libtest_mod.end);
	LM_PRINTF(LM_STR("====================\n"));

	LM_GetPage(mod.base, &page);
	LM_PRINTF(LM_STR("[*] Page Base:  %p\n"), page.base);
	LM_PRINTF(LM_STR("[*] Page Size:  %p\n"), (void *)page.size);
	LM_PRINTF(LM_STR("[*] Page End:   %p\n"), page.end);
	LM_PRINTF(LM_STR("[*] Page Prot:  %d\n"), (int)page.prot);
	LM_PRINTF(LM_STR("[*] Page Flags: %d\n"), (int)page.flags);
	LM_PRINTF(LM_STR("====================\n"));

	LM_ReadMemory((lm_address_t)&val, (lm_byte_t *)&rdbuf, sizeof(rdbuf));
	LM_WriteMemory((lm_address_t)&val, (lm_bstring_t)&wrbuf, sizeof(wrbuf));
	data_scan = LM_DataScan(scanme, sizeof(scanme), (lm_address_t)&scanme[-10], (lm_address_t)&scanme[10]);
	pattern_scan = LM_PatternScan(scanme, mask, (lm_address_t)&scanme[-10], (lm_address_t)&scanme[10]);
	sig_scan = LM_SigScan(signature, (lm_address_t)&scanme[-10], (lm_address_t)&scanme[10]);
	alloc = LM_AllocMemory(1, LM_PROT_RW);
	LM_ProtMemory(alloc, 1, LM_PROT_XRW, &alloc_oldprot);
	LM_GetPage(alloc, &page);
	alloc_prot = page.prot;
	LM_FreeMemory(alloc, 1);

	LM_PRINTF(LM_STR("[*] Read Value:    %li\n"), rdbuf);
	LM_PRINTF(LM_STR("[*] Written Value: %li\n"), wrbuf);
	LM_PRINTF(LM_STR("[*] Real Value:    %li\n"), val);
	LM_PRINTF(LM_STR("[*] ScanMe Addr:  %p\n"), (void *)scanme);
	LM_PRINTF(LM_STR("[*] Data Scan:    %p\n"), data_scan);
	LM_PRINTF(LM_STR("[*] Pattern Scan: %p\n"), pattern_scan);
	LM_PRINTF(LM_STR("[*] Sig Scan:     %p\n"), sig_scan);
	LM_PRINTF(LM_STR("[*] Alloc:    %p\n"), alloc);
	LM_PRINTF(LM_STR("[*] Prot:     %d\n"), alloc_prot);
	LM_PRINTF(LM_STR("[*] Old Prot: %d\n"), alloc_oldprot);
	LM_PRINTF(LM_STR("====================\n"));

	LM_PRINTF(LM_STR("[-] Test 1\n"));

	LM_CloseProcess(&proc);

	return 0;
}