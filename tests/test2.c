#include <libmem/libmem.h>

#if LM_CHARSET == LM_CHARSET_UC
#define LM_PRINTF wprintf
#else
#define LM_PRINTF printf
#endif

lm_bool_t _LM_EnumProcessesCallback(lm_process_t *pproc,
				    lm_void_t    *arg)
{
	lm_size_t *counter = (lm_size_t *)arg;

	LM_PRINTF(LM_STR("PID: %d | PPID: %d | Bits: %zu | Name: %s | Path: %s\n"),
		  (int)pproc->pid, (int)pproc->ppid, (size_t)pproc->bits, pproc->name, pproc->path);

	*counter += 1;
	if (*counter >= 5)
		return LM_FALSE;

	return LM_TRUE;
}

int
main()
{
	lm_size_t    counter = 0;
	lm_process_t proc;
	lm_thread_t  thread;
	lm_module_t  mod;
	lm_address_t main_sym;
	/*
	lm_module_t  libtest_mod;
	lm_char_t    libtest_modname[LM_PATH_MAX];
	lm_char_t    libtest_modpath[LM_PATH_MAX];
	*/
	lm_page_t    page;
	lm_address_t val_sym;
	lm_int32_t   rdbuf;
	lm_int32_t   rdbuf2;
	lm_int32_t   wrbuf = 69;
	lm_byte_t    scanme[] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };
	lm_char_t    mask[] = LM_STR("xxxxxxxxxx");
	lm_char_t    signature[] = LM_STR("10 20 30 40 50 60 70 80 90 A0");
	lm_address_t data_scan;
	lm_address_t pattern_scan;
	lm_address_t sig_scan;
	lm_address_t alloc;
	lm_prot_t    alloc_prot;
	lm_prot_t    alloc_oldprot;

	LM_PRINTF(LM_STR("[+] Test 2\n"));

	LM_EnumProcesses(_LM_EnumProcessesCallback, (lm_void_t *)&counter);
	LM_PRINTF(LM_STR("====================\n"));

	LM_FindProcess(TEST1_NAME, &proc);
	LM_GetThreadEx(&proc, &thread);

	LM_PRINTF(LM_STR("[*] Process Name: %s\n"), proc.name);
	LM_PRINTF(LM_STR("[*] Process Path: %s\n"), proc.path);
	LM_PRINTF(LM_STR("[*] PID:  %d\n"), proc.pid);
	LM_PRINTF(LM_STR("[*] PPID: %d\n"), proc.ppid);
	LM_PRINTF(LM_STR("[*] TID:  %d\n"), thread.tid);
	LM_PRINTF(LM_STR("[*] Bits: %lu\n"), proc.bits);
	LM_PRINTF(LM_STR("====================\n"));

	LM_FindModuleEx(&proc, proc.path, &mod);
	main_sym = LM_FindSymbolAddress(&mod, "main");
	val_sym = LM_FindSymbolAddress(&mod, "val");
	LM_PRINTF(LM_STR("[*] Module Name: %s\n"), mod.name);
	LM_PRINTF(LM_STR("[*] Module Path: %s\n"), mod.path);
	LM_PRINTF(LM_STR("[*] Module Base: %p\n"), (void *)mod.base);
	LM_PRINTF(LM_STR("[*] Module Size: %p\n"), (void *)mod.size);
	LM_PRINTF(LM_STR("[*] Module End:  %p\n"), (void *)mod.end);
	LM_PRINTF(LM_STR("[*] Main Addr:   %p\n"), (void *)main_sym);
	LM_PRINTF(LM_STR("[*] Val Addr:    %p\n"), (void *)val_sym);
	LM_PRINTF(LM_STR("====================\n"));

	/*
	LM_LoadModuleEx(&proc, LM_STR(LIBTEST_PATH), &libtest_mod);
	LM_GetModuleNameEx(&proc, libtest_mod, libtest_modname, LM_ARRLEN(libtest_modname));
	LM_GetModulePathEx(&proc, libtest_mod, libtest_modpath, LM_ARRLEN(libtest_modpath));
	LM_UnloadModuleEx(&proc, libtest_mod);
	LM_PRINTF(LM_STR("[*] Module Name: %s\n"), libtest_modname);
	LM_PRINTF(LM_STR("[*] Module Path: %s\n"), libtest_modpath);
	LM_PRINTF(LM_STR("[*] Module Base: %p\n"), libtest_mod.base);
	LM_PRINTF(LM_STR("[*] Module Size: %p\n"), (void *)libtest_mod.size);
	LM_PRINTF(LM_STR("[*] Module End:  %p\n"), libtest_mod.end);
	LM_PRINTF(LM_STR("====================\n"));
	*/

	LM_GetPageEx(&proc, mod.base, &page);
	LM_PRINTF(LM_STR("[*] Page Base:  %p\n"), (void *)page.base);
	LM_PRINTF(LM_STR("[*] Page Size:  %p\n"), (void *)page.size);
	LM_PRINTF(LM_STR("[*] Page End:   %p\n"), (void *)page.end);
	LM_PRINTF(LM_STR("[*] Page Prot:  %d\n"), (int)page.prot);
	LM_PRINTF(LM_STR("====================\n"));

	LM_ReadMemoryEx(&proc, val_sym, (lm_byte_t *)&rdbuf, sizeof(rdbuf));
	LM_WriteMemoryEx(&proc, val_sym, (lm_bytearr_t)&wrbuf, sizeof(wrbuf));
	LM_ReadMemoryEx(&proc, val_sym, (lm_byte_t *)&rdbuf2, sizeof(rdbuf));
	data_scan = LM_DataScanEx(&proc, scanme, sizeof(scanme), mod.base, mod.size);
	pattern_scan = LM_PatternScanEx(&proc, scanme, mask, mod.base, mod.size);
	sig_scan = LM_SigScanEx(&proc, signature, mod.base, mod.size);
	alloc = LM_AllocMemoryEx(&proc, 1, LM_PROT_RW);
	LM_ProtMemoryEx(&proc, alloc, 1, LM_PROT_XRW, &alloc_oldprot);
	LM_GetPageEx(&proc, alloc, &page);
	alloc_prot = page.prot;
	LM_FreeMemoryEx(&proc, alloc, 1);

	LM_PRINTF(LM_STR("[*] Read Value:    %d\n"), rdbuf);
	LM_PRINTF(LM_STR("[*] Written Value: %d\n"), wrbuf);
	LM_PRINTF(LM_STR("[*] Real Value:    %d\n"), rdbuf2);
	LM_PRINTF(LM_STR("[*] Data Scan:    %p\n"), (void *)data_scan);
	LM_PRINTF(LM_STR("[*] Pattern Scan: %p\n"), (void *)pattern_scan);
	LM_PRINTF(LM_STR("[*] Sig Scan:     %p\n"), (void *)sig_scan);
	LM_PRINTF(LM_STR("[*] Alloc:    %p\n"), (void *)alloc);
	LM_PRINTF(LM_STR("[*] Prot:     %d\n"), (int)alloc_prot);
	LM_PRINTF(LM_STR("[*] Old Prot: %d\n"), (int)alloc_oldprot);
	LM_PRINTF(LM_STR("====================\n"));

	LM_PRINTF(LM_STR("[-] Test 2\n"));

	return 0;
}
