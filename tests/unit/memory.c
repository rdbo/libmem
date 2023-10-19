#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

#define ALLOCSIZE 1024
#define BADPROT 0xDEADBEEF

char *test_LM_AllocMemory(lm_address_t *palloc)
{
	*palloc = LM_AllocMemory(ALLOCSIZE, LM_PROT_XRW);
	mu_assert("failed to allocate memory", *palloc != LM_ADDRESS_BAD);
	
	printf("<ADDRESS: %p> ", (void *)*palloc);
	fflush(stdout);
	
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_AllocMemory(0, LM_PROT_NONE) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad arguments (invalid prot)", LM_AllocMemory(ALLOCSIZE, BADPROT) == LM_ADDRESS_BAD);
	
	return NULL;
}

char *test_LM_FreeMemory(lm_address_t *palloc)
{
	mu_assert("failed to deallocate memory", LM_FreeMemory(*palloc, ALLOCSIZE) == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid alloc)", LM_FreeMemory(LM_ADDRESS_BAD, ALLOCSIZE) == LM_FALSE);
	/* NOTE: size can be 0 on Windows, where that parameter is unused - on other platforms, it's recommended to pass the actual size or '1' to deallocate the full page */
	// mu_assert("function attempted to run with bad arguments (invalid size)", LM_FreeMemory(*palloc, 0) == LM_FALSE);

	return NULL;
}

char *test_LM_ReadMemory(void *arg)
{
	char buf[] = { 'A', 'B', 'C', 'D' };
	lm_byte_t buf_copy[sizeof(buf)] = { 0 };

	mu_assert("failed to read buffer into copy buffer", LM_ReadMemory((lm_address_t)buf, buf_copy, sizeof(buf_copy)) == sizeof(buf_copy));
	mu_assert("copy buffer does not match original buffer", memcmp(buf, buf_copy, sizeof(buf_copy)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid src)", LM_ReadMemory(LM_ADDRESS_BAD, buf_copy, sizeof(buf_copy)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid dst)", LM_ReadMemory((lm_address_t)buf, LM_ADDRESS_BAD, sizeof(buf_copy)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_ReadMemory((lm_address_t)buf, buf_copy, 0) == 0);
	
	return NULL;
}

char *test_LM_WriteMemory(void *arg)
{
	int number = 0;
	int new_number = 1337;

	mu_assert("failed to read buffer into copy buffer", LM_WriteMemory((lm_address_t)&number, (lm_bytearr_t)&new_number, sizeof(new_number)) == sizeof(new_number));
	mu_assert("written buffer does not match src buffer", number == new_number);
	mu_assert("function attempted to run with bad arguments (invalid dst)", LM_WriteMemory(LM_ADDRESS_BAD, (lm_bytearr_t)&new_number, sizeof(new_number)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid src)", LM_WriteMemory((lm_address_t)&number, LM_ADDRESS_BAD, sizeof(new_number)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_WriteMemory((lm_address_t)&number, (lm_bytearr_t)&new_number, 0) == 0);
	
	return NULL;
}

char *test_LM_SetMemory(void *arg)
{
	char buf[] = { 'H', 'E', 'L', 'L', 'O' };
	lm_byte_t new_bytes = 0xFF;
	size_t i;

	mu_assert("failed to set bytes of buffer", LM_SetMemory((lm_address_t)buf, new_bytes, sizeof(buf)) == sizeof(buf));
	for (i = 0; i < sizeof(buf); ++i) {
		mu_assert("set memory region contains invalid bytes", (lm_byte_t)buf[i] == new_bytes);
	}

	mu_assert("function attempted to run with bad arguments (invalid dst)", LM_SetMemory(LM_ADDRESS_BAD, new_bytes, sizeof(buf)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_SetMemory((lm_address_t)buf, new_bytes, 0) == 0);

	return NULL;
}

char *test_LM_AllocMemoryEx(struct memory_args *arg)
{
	lm_process_t *ptargetproc = arg->ptargetproc;
	lm_address_t *palloc = arg->palloc;

	*palloc = LM_AllocMemoryEx(ptargetproc, ALLOCSIZE, LM_PROT_XRW);
	mu_assert("failed to allocate memory", *palloc != LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_AllocMemoryEx(LM_NULLPTR, ALLOCSIZE, LM_PROT_XRW) == LM_ADDRESS_BAD);

	printf("<ADDRESS: %p> ", (void *)*palloc);
	fflush(stdout);
	
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_AllocMemoryEx(ptargetproc, 0, LM_PROT_XRW) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad arguments (invalid prot)", LM_AllocMemoryEx(ptargetproc, ALLOCSIZE, BADPROT) == LM_ADDRESS_BAD);

	return NULL;
}

char *test_LM_FreeMemoryEx(struct memory_args *arg)
{
	lm_process_t *ptargetproc = arg->ptargetproc;
	lm_address_t *palloc = arg->palloc;

	mu_assert("failed to deallocate memory", LM_FreeMemoryEx(ptargetproc, *palloc, ALLOCSIZE) == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_FreeMemoryEx(LM_NULLPTR, *palloc, ALLOCSIZE) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid address)", LM_FreeMemoryEx(ptargetproc, LM_ADDRESS_BAD, ALLOCSIZE) == LM_FALSE);

	return NULL;
}
