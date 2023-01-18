#include <libmem/libmem.h>

#if LM_CHARSET == LM_CHARSET_UC
#define LM_PRINTF wprintf
#else
#define LM_PRINTF printf
#endif

#if LM_OS == LM_OS_WIN
#define LM_SLEEP(t) Sleep(t * 1000)
#else
#define LM_SLEEP(t) sleep(t)
#endif

lm_int32_t val = 10;
lm_byte_t  scanme[] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };

void
some_function(int a, int b)
{
	printf("Some Function\n");
	printf("%d + %d = %d\n", a, b, a + b);
	printf("Don't forget to unhook me\n");
}

typedef void (*some_function_t)(int a, int b);
some_function_t some_function_orig;

void hk_some_function(int a, int b)
{
	printf("Hooked Some Function\n");
	printf("Original A: %d\n", a);
	printf("Original B: %d\n", b);
	some_function_orig(420, 917);
}

LM_API_EXPORT int
main()
{
	lm_process_t proc;
	lm_thread_t  thread;
	lm_module_t  mod;
	lm_address_t main_sym;
	lm_module_t  libtest_mod;
	lm_page_t    page;
	lm_int32_t   rdbuf;
	lm_int32_t   wrbuf = 1337;
	lm_char_t    mask[] = LM_STR("xxxxxxxxxx");
	lm_char_t    signature[] = LM_STR("10 20 30 40 50 60 70 80 90 A0");
	lm_address_t data_scan;
	lm_address_t pattern_scan;
	lm_address_t sig_scan;
	lm_address_t alloc;
	lm_prot_t    alloc_prot;
	lm_prot_t    alloc_oldprot;
	lm_inst_t    inst;
	lm_cchar_t   code[255];
	lm_size_t    asm_count;
	lm_size_t    disasm_count;
	lm_size_t    disasm_bytes = 0;
	lm_size_t    tramp_size;

	LM_PRINTF(LM_STR("[+] Test 1\n"));

	LM_GetProcess(&proc);
	LM_GetThread(&thread);

	LM_PRINTF(LM_STR("[*] Process Name: %s\n"), proc.name);
	LM_PRINTF(LM_STR("[*] Process Path: %s\n"), proc.path);
	LM_PRINTF(LM_STR("[*] PID:  %d\n"), proc.pid);
	LM_PRINTF(LM_STR("[*] PPID: %d\n"), proc.ppid);
	LM_PRINTF(LM_STR("[*] TID:  %d\n"), thread.tid);
	LM_PRINTF(LM_STR("[*] Bits: %lu\n"), proc.bits);
	LM_PRINTF(LM_STR("====================\n"));

	LM_FindModule(proc.path, &mod);
	main_sym = LM_FindSymbolAddress(&mod, "main");
	LM_PRINTF(LM_STR("[*] Module Name:    %s\n"), mod.name);
	LM_PRINTF(LM_STR("[*] Module Path:    %s\n"), mod.path);
	LM_PRINTF(LM_STR("[*] Module Base:    %p\n"), (void *)mod.base);
	LM_PRINTF(LM_STR("[*] Module Size:    %p\n"), (void *)mod.size);
	LM_PRINTF(LM_STR("[*] Module End:     %p\n"), (void *)mod.end);
	LM_PRINTF(LM_STR("[*] Main Addr:      %p\n"), (void *)main_sym);
	LM_PRINTF(LM_STR("[*] Real Main Addr: %p\n"), (void *)main);
	LM_PRINTF(LM_STR("====================\n"));

	LM_PRINTF(LM_STR("[*] Module to Load: %s\n"), LIBTEST_PATH);
	LM_LoadModule(LM_STR(LIBTEST_PATH), &libtest_mod);
	LM_UnloadModule(&libtest_mod);
	LM_PRINTF(LM_STR("[*] Module Name: %s\n"), libtest_mod.name);
	LM_PRINTF(LM_STR("[*] Module Path: %s\n"), libtest_mod.path);
	LM_PRINTF(LM_STR("[*] Module Base: %p\n"), (void *)libtest_mod.base);
	LM_PRINTF(LM_STR("[*] Module Size: %p\n"), (void *)libtest_mod.size);
	LM_PRINTF(LM_STR("[*] Module End:  %p\n"), (void *)libtest_mod.end);
	LM_PRINTF(LM_STR("====================\n"));

	LM_GetPage(mod.base, &page);
	LM_PRINTF(LM_STR("[*] Page Base:  %p\n"), (void *)page.base);
	LM_PRINTF(LM_STR("[*] Page Size:  %p\n"), (void *)page.size);
	LM_PRINTF(LM_STR("[*] Page End:   %p\n"), (void *)page.end);
	LM_PRINTF(LM_STR("[*] Page Prot:  %d\n"), (int)page.prot);
	LM_PRINTF(LM_STR("====================\n"));

	LM_ReadMemory((lm_address_t)&val, (lm_byte_t *)&rdbuf, sizeof(rdbuf));
	LM_WriteMemory((lm_address_t)&val, (lm_bytearr_t)&wrbuf, sizeof(wrbuf));
	data_scan = LM_DataScan(scanme, sizeof(scanme), (lm_address_t)&scanme[-10], sizeof(scanme) + 10);
	pattern_scan = LM_PatternScan(scanme, mask, (lm_address_t)&scanme[-10], sizeof(scanme) + 10);
	sig_scan = LM_SigScan(signature, (lm_address_t)&scanme[-10], sizeof(scanme) + 10);
	alloc = LM_AllocMemory(1, LM_PROT_RW);
	LM_ProtMemory(alloc, 1, LM_PROT_XRW, &alloc_oldprot);
	LM_GetPage(alloc, &page);
	alloc_prot = page.prot;
	LM_FreeMemory(alloc, 1);

	LM_PRINTF(LM_STR("[*] Read Value:    %d\n"), rdbuf);
	LM_PRINTF(LM_STR("[*] Written Value: %d\n"), wrbuf);
	LM_PRINTF(LM_STR("[*] Real Value:    %d\n"), val);
	LM_PRINTF(LM_STR("[*] ScanMe Addr:  %p\n"), (void *)scanme);
	LM_PRINTF(LM_STR("[*] Data Scan:    %p\n"), (void *)data_scan);
	LM_PRINTF(LM_STR("[*] Pattern Scan: %p\n"), (void *)pattern_scan);
	LM_PRINTF(LM_STR("[*] Sig Scan:     %p\n"), (void *)sig_scan);
	LM_PRINTF(LM_STR("[*] Alloc:    %p\n"), (void *)alloc);
	LM_PRINTF(LM_STR("[*] Prot:     %d\n"), (int)alloc_prot);
	LM_PRINTF(LM_STR("[*] Old Prot: %d\n"), (int)alloc_oldprot);
	LM_PRINTF(LM_STR("====================\n"));

	LM_PRINTF(LM_STR("[*] Dissassembly (main):\n"));
	LM_ProtMemory((lm_address_t)main, 100, LM_PROT_XRW, LM_NULLPTR);
	for (disasm_count = 0; disasm_count < 5; ++disasm_count) {
		memset((void *)&inst, 0x0, sizeof(inst));
		LM_Disassemble((lm_address_t)LM_OFFSET(main_sym, disasm_bytes), &inst);
		LM_PRINTF(LM_STR("%s %s\n"), inst.mnemonic, inst.op_str);
		disasm_bytes += inst.size;
	}
	LM_PRINTF(LM_STR("...\n"));

	LM_PRINTF(LM_STR("====================\n"));

	/* Reassemble the bytes from the disassembly */
	LM_PRINTF(LM_STR("[*] Assembly:\n"));
	LM_SNPRINTF(code, sizeof(code), LM_STR("%s %s"), inst.mnemonic, inst.op_str);
	LM_PRINTF(LM_STR("%s: "), code);
	LM_Assemble(code, &inst);
	for (asm_count = 0; asm_count < inst.size; ++asm_count) {
		printf("0x%02x ", inst.bytes[asm_count]);
	}
	printf("\n");
	LM_PRINTF(LM_STR("====================\n"));

	LM_PRINTF(LM_STR("[*] Some Function Hook:\n"));

	tramp_size = LM_HookCode((lm_address_t)some_function,
				 (lm_address_t)hk_some_function,
				 (lm_address_t *)&some_function_orig);

	LM_PRINTF(LM_STR("[*] Some Function Trampoline: %p\n"), (void *)some_function_orig);

	some_function(10, 10);

	LM_UnhookCode((lm_address_t)some_function, (lm_address_t)some_function_orig, tramp_size);

	printf("\nUnhooked\n\n");
	some_function(5, 5);

	LM_PRINTF(LM_STR("====================\n"));

	LM_PRINTF(LM_STR("[-] Test 1\n"));

	LM_PRINTF(LM_STR("[*] Waiting for Test 2...\n"));
	for (;;) {
		LM_SLEEP(1);
	}

	return 0;
}
