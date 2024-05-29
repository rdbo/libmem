#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define UNIT_TEST_P(func, arg) { \
	extern char *test_##func(void *); \
	char *result; \
	printf("%s... ", #func); \
	fflush(stdout); \
	result = test_##func(arg); \
	if (result) { \
		printf("ERROR: %s\n", result); \
		exit(1); \
	} \
	printf("OK\n"); \
}

#define UNIT_TEST(func) UNIT_TEST_P(func, NULL)

void test_asm()
{
	UNIT_TEST(LM_Assemble);
	UNIT_TEST(LM_AssembleEx);
	UNIT_TEST(LM_Disassemble);
	UNIT_TEST(LM_DisassembleEx);
}

void test_process(lm_process_t *pcurproc, lm_process_t *ptargetproc)
{
	UNIT_TEST(LM_EnumProcesses);
	UNIT_TEST_P(LM_GetProcess, pcurproc);
	UNIT_TEST_P(LM_GetProcessEx, pcurproc);
	UNIT_TEST_P(LM_FindProcess, ptargetproc);
	UNIT_TEST_P(LM_IsProcessAlive, pcurproc);
	UNIT_TEST(LM_GetSystemBits);
}

void test_thread(lm_process_t *pcurproc, lm_process_t *ptargetproc, lm_thread_t *pcurthread, lm_thread_t *ptargetthread)
{
	struct thread_args arg;
	arg.pcurproc = pcurproc;
	arg.ptargetproc = ptargetproc;
	arg.pcurthread = pcurthread;
	arg.ptargetthread = ptargetthread;
	
	UNIT_TEST_P(LM_GetThread, &arg);
	UNIT_TEST_P(LM_EnumThreads, &arg);
	UNIT_TEST_P(LM_GetThreadEx, &arg);
	UNIT_TEST_P(LM_EnumThreadsEx, &arg);
	UNIT_TEST_P(LM_GetThreadProcess, &arg);
}

void test_memory(lm_process_t *ptargetproc)
{
	lm_address_t alloc;
	struct memory_args arg;
	arg.ptargetproc = ptargetproc;
	arg.palloc = &alloc;

	UNIT_TEST_P(LM_AllocMemory, &alloc);
	UNIT_TEST_P(LM_ProtMemory, &alloc);
	UNIT_TEST_P(LM_FreeMemory, &alloc);
	UNIT_TEST(LM_ReadMemory);
	UNIT_TEST(LM_WriteMemory);
	UNIT_TEST(LM_SetMemory);
	UNIT_TEST(LM_DeepPointer);
	UNIT_TEST_P(LM_AllocMemoryEx, &arg);
	UNIT_TEST_P(LM_ProtMemoryEx, &arg);
	UNIT_TEST_P(LM_WriteMemoryEx, &arg);
	UNIT_TEST_P(LM_SetMemoryEx, &arg);
	UNIT_TEST_P(LM_ReadMemoryEx, &arg);
	UNIT_TEST_P(LM_DeepPointerEx, &arg);
	UNIT_TEST_P(LM_FreeMemoryEx, &arg);
}

void test_hook(lm_process_t *ptargetproc)
{
	lm_module_t mod;
	struct hook_args arg;
	arg.ptargetproc = ptargetproc;
	arg.ptargetmod = &mod;

	/* TODO: Retrieve module from 'module' tests and reuse here! */
	assert(LM_FindModuleEx(ptargetproc, ptargetproc->path, &mod) == LM_TRUE);
	
	UNIT_TEST_P(LM_HookCode, &arg);
	UNIT_TEST_P(LM_UnhookCode, &arg);
	UNIT_TEST_P(LM_HookCodeEx, &arg);
	UNIT_TEST_P(LM_UnhookCodeEx, &arg);
}

void test_module(lm_process_t *pcurproc, lm_process_t *ptargetproc)
{
	lm_module_t mod;
	struct load_module_args arg;
	arg.ptargetproc = ptargetproc;
	arg.pmod = &mod;

	UNIT_TEST_P(LM_EnumModules, pcurproc);
	UNIT_TEST_P(LM_EnumModulesEx, ptargetproc);
	UNIT_TEST_P(LM_FindModule, pcurproc);
	UNIT_TEST_P(LM_FindModuleEx, ptargetproc);
	UNIT_TEST_P(LM_LoadModule, &mod);
	UNIT_TEST_P(LM_UnloadModule, &mod);
	UNIT_TEST_P(LM_LoadModuleEx, &arg);
	/* UNIT_TEST_P(LM_UnloadModuleEx, &arg); */ /* NOTE: Disabled due to not working under glibc (Linux) */
}

void test_segment(lm_process_t *pcurproc, lm_process_t *ptargetproc)
{
	UNIT_TEST_P(LM_EnumSegments, pcurproc);
	UNIT_TEST_P(LM_EnumSegmentsEx, pcurproc);
	UNIT_TEST_P(LM_FindSegment, pcurproc);
	UNIT_TEST_P(LM_FindSegmentEx, ptargetproc);
}

void test_symbol(lm_process_t *pcurproc, lm_process_t *ptargetproc)
{
	/* TODO: Retrieve module from 'module' tests and reuse here! */
	lm_module_t mod;
	lm_module_t target_mod;
	struct find_symbol_args arg;
	
	assert(LM_FindModule(pcurproc->name, &mod) == LM_TRUE);
	assert(LM_FindModuleEx(ptargetproc, ptargetproc->name, &target_mod) == LM_TRUE);

	arg.curmod = &mod;
	arg.targetmod = &target_mod;
	
	UNIT_TEST_P(LM_EnumSymbols, &mod);
	UNIT_TEST_P(LM_FindSymbolAddress, &arg);
	UNIT_TEST(LM_DemangleSymbol);
	UNIT_TEST(LM_FreeDemangledSymbol);
	UNIT_TEST_P(LM_EnumSymbolsDemangled, &mod);
	UNIT_TEST_P(LM_FindSymbolAddressDemangled, &mod);
}

void test_vmt()
{
	lm_vmt_t vmt;

	UNIT_TEST_P(LM_VmtNew, &vmt);
	UNIT_TEST_P(LM_VmtHook, &vmt);
	UNIT_TEST_P(LM_VmtGetOriginal, &vmt);
	UNIT_TEST_P(LM_VmtUnhook, &vmt);
	UNIT_TEST_P(LM_VmtReset, &vmt);
	UNIT_TEST_P(LM_VmtFree, &vmt);
}

void test_scan(lm_process_t *ptargetproc)
{
	struct scan_args arg;
	arg.ptargetproc = ptargetproc;
	arg.scanaddr = LM_AllocMemoryEx(ptargetproc, sizeof(scanbuf), LM_PROT_XRW);
	assert(arg.scanaddr != LM_ADDRESS_BAD);

	assert(LM_WriteMemoryEx(ptargetproc, arg.scanaddr, (lm_bytearray_t)scanbuf, sizeof(scanbuf)) == sizeof(scanbuf));
	
	UNIT_TEST(LM_DataScan);
	UNIT_TEST_P(LM_DataScanEx, &arg);
	UNIT_TEST(LM_PatternScan);
	UNIT_TEST_P(LM_PatternScanEx, &arg);
	UNIT_TEST(LM_SigScan);
	UNIT_TEST_P(LM_SigScanEx, &arg);

	LM_FreeMemoryEx(ptargetproc, arg.scanaddr, sizeof(scanbuf));
}

LM_API_EXPORT int
main()
{
	lm_process_t current_process;
	lm_process_t target_process;
	lm_thread_t  current_thread;
	lm_thread_t  target_thread;
	lm_module_t  target_module;
	
	printf("[*] Unit Tests\n");
	printf("[*] NOTE: Some operations may require root access (or Administrator)\n");

	/*
	lm_byte_t *payload;
	lm_size_t size = LM_AssembleEx("bx r0", LM_ARCH_ARMV7, 0xdeadbeef, &payload);
	printf("payload (size: %zu): \"", size);
	for (size_t i = 0; i < size; ++i) {
		printf("\\x%hhx", payload[i]);
	}
	printf("\"\n");

	exit(0);
	*/

	test_asm();
	test_process(&current_process, &target_process);
	test_thread(&current_process, &target_process, &current_thread, &target_thread);
	test_segment(&current_process, &target_process);
	test_memory(&target_process);
	test_module(&current_process, &target_process);
	test_symbol(&current_process, &target_process);
	test_hook(&target_process);
	test_scan(&target_process);
	test_vmt();

	return 0;
}
