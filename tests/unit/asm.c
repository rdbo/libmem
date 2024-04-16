#include <libmem/libmem.h>
#include "minunit.h"
#include <stdio.h>
#include <memory.h>

#define RTADDR 0x69420

#define X86_32_INST "mov eax, 0x1337"
#define X86_32_INST_BYTES "\xB8\x39\x05\x00\x00"
#define X86_32_INST_SIZE (sizeof(X86_32_INST_BYTES) - 1) /* -1 is necessary to remove the NULL terminator */

#define X86_64_INST "movabs rax, 1337"
#define X86_64_INST_BYTES "\x48\xB8\x39\x05\x00\x00\x00\x00\x00\x00"
#define X86_64_INST_SIZE (sizeof(X86_64_INST_BYTES) - 1)

char *test_LM_Assemble(void *arg)
{
	char *code;
	size_t size;
	char *payload;
	lm_inst_t inst;

	/* TODO: Make macro for this */
	if (LM_GetArchitecture() == LM_ARCH_X86) {
		if (LM_GetBits() == 64) {
			code = X86_64_INST;
			size = X86_64_INST_SIZE;
			payload = X86_64_INST_BYTES;
		} else {
			code = X86_32_INST;
			size = X86_32_INST_SIZE;
			payload = X86_32_INST_BYTES;
		}
	} else {
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
