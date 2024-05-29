#include <libmem/libmem.h>
#include "minunit.h"
#include <stdio.h>
#include <memory.h>

#define RTADDR 0x69420

#define X86_INST "mov eax, 1337"
#define X86_INST_BYTES "\xB8\x39\x05\x00\x00"
#define X86_INST_SIZE (sizeof(X86_INST_BYTES) - 1) /* -1 is necessary to remove the NULL terminator */

#define X86_ASM "push ebp; mov ebp, esp; mov eax, 1337; call 0xdeadbeef; mov esp, ebp; pop ebp; ret"
#define X86_ASM_BYTES "\x55\x89\xE5\xB8\x39\x05\x00\x00\xE8\xC2\x2A\xA7\xDE\x89\xEC\x5D\xC3"
#define X86_ASM_SIZE (sizeof(X86_ASM_BYTES) - 1)
#define X86_ASM_INST_COUNT 7

#define X64_INST "movabs rax, 1337"
#define X64_INST_BYTES "\x48\xB8\x39\x05\x00\x00\x00\x00\x00\x00"
#define X64_INST_SIZE (sizeof(X64_INST_BYTES) - 1)

#define X64_ASM "push rbp; mov rbp, rsp; mov eax, [rip + 1337]; call rax; mov rsp, rbp; pop rbp; ret"
#define X64_ASM_BYTES "\x55\x48\x89\xE5\x8B\x05\x39\x05\x00\x00\xFF\xD0\x48\x89\xEC\x5D\xC3"
#define X64_ASM_SIZE (sizeof(X64_ASM_BYTES) - 1)
#define X64_ASM_INST_COUNT 7

#define TEST_LM_ASSEMBLE_EX(arch) \
{ \
	lm_byte_t *payload; \
	lm_size_t size; \
	lm_bool_t check_size; \
	lm_bool_t check_content; \
	lm_size_t i; \
\
	size = LM_AssembleEx(arch##_##ASM, LM_ARCH_##arch, RTADDR, &payload); \
	mu_assert("failed to assemble " #arch " code", size > 0); \
	check_size = size == arch##_ASM_SIZE; \
	if (check_size) check_content = memcmp(payload, arch##_##ASM_BYTES, size) == 0; \
	printf("<%s PAYLOAD: { ", #arch); \
	for (i = 0; i < size; ++i) printf("%hhx ", payload[i]); \
	printf("}>"); \
	LM_FreePayload(payload); \
	mu_assert("payload size of " #arch " is incorrect", check_size); \
	\
	fflush(stdout); \
	\
	mu_assert("payload content of " #arch " does not match expected bytes", check_content); \
}

#define TEST_LM_DISASSEMBLE_EX(arch) \
{ \
	lm_byte_t *payload = arch##_##ASM_BYTES; \
	lm_inst_t *insts; \
	lm_size_t inst_count; \
\
	inst_count = LM_DisassembleEx((lm_address_t)payload, LM_ARCH_##arch, arch##_##ASM_SIZE, 0, RTADDR, &insts); \
	mu_assert("failed to disassemble " #arch " payload", inst_count > 0); \
\
	printf("<%s INST COUNT: %zd> <%s EXPECTED INST COUNT: %d> ", #arch, inst_count, #arch, arch##_##ASM_INST_COUNT); \
	fflush(stdout); \
\
	LM_FreeInstructions(insts); \
	mu_assert("instruction count does not match expected value", inst_count == arch##_##ASM_INST_COUNT); \
}

char *test_LM_Assemble(void *arg)
{
	char *code;
	size_t size;
	char *payload;
	lm_inst_t inst;

	/* TODO: Make macro for this */
	switch (LM_GetArchitecture()) {
	case LM_ARCH_X64:
		code = X64_INST;
		size = X64_INST_SIZE;
		payload = X64_INST_BYTES;
		break;
	case LM_ARCH_X86:
		code = X86_INST;
		size = X86_INST_SIZE;
		payload = X86_INST_BYTES;
		break;
	default:
		printf("<WARN: Architecture untested>");
		fflush(stdout);
		return NULL;
	}

	printf("<CODE: %s> <EXPECTED SIZE: %zd> ", code, size);
	fflush(stdout);

	mu_assert("failed to assemble code", LM_Assemble(code, &inst) != 0);

	printf("<SIZE: %zd> ", inst.size);
	fflush(stdout);

	mu_assert("instruction size is incorrect", inst.size == size);
	mu_assert("instruction bytes do not match expected payload", memcmp(inst.bytes, payload, size) == 0);

	return NULL;
}

char *test_LM_AssembleEx(void *arg)
{
	TEST_LM_ASSEMBLE_EX(X86);
	TEST_LM_ASSEMBLE_EX(X64);

	return NULL;
}

char *test_LM_Disassemble(void *arg)
{
	char *code;
	size_t size;
	char *payload;
	lm_inst_t inst;

	/* TODO: Make macro for this */
	switch (LM_GetArchitecture()) {
	case LM_ARCH_X64:
		code = X64_INST;
		size = X64_INST_SIZE;
		payload = X64_INST_BYTES;
		break;
	case LM_ARCH_X86:
		code = X86_INST;
		size = X86_INST_SIZE;
		payload = X86_INST_BYTES;
		break;
	default:
		printf("<WARN: Architecture untested>");
		fflush(stdout);
		return NULL;
	}

	printf("<EXPECTED SIZE: %zd> ", size);
	fflush(stdout);

	mu_assert("failed to disassemble code", LM_Disassemble((lm_address_t)payload, &inst) != 0);

	printf("<SIZE: %zd> <DISASM: %s %s> ", inst.size, inst.mnemonic, inst.op_str);
	fflush(stdout);

	mu_assert("instruction size is incorrect", inst.size == size);
	/* TODO: Don't rely on mnemonic being smaller than code, it may lead to buffer overflow */
	mu_assert("instruction mnemonic does not match expected payload", strncmp(inst.mnemonic, code, strlen(inst.mnemonic)) == 0);

	return NULL;
}

char *test_LM_DisassembleEx(void *arg)
{
	TEST_LM_DISASSEMBLE_EX(X86);
	TEST_LM_DISASSEMBLE_EX(X64);

	return NULL;
}
