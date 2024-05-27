#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"
#include <stdint.h>
#include <stddef.h>

#define ALLOCSIZE 0
#define ALLOCPROT LM_PROT_XRW
#define BADPROT 0xDEADBEEF

/* TODO: Check if allocations have correct memory protection flags */

char *test_LM_AllocMemory(lm_address_t *palloc)
{
	*palloc = LM_AllocMemory(ALLOCSIZE, ALLOCPROT);
	mu_assert("failed to allocate memory", *palloc != LM_ADDRESS_BAD);
	
	printf("<ADDRESS: %p> ", (void *)*palloc);
	fflush(stdout);

	/* NOTE: LM_AllocMemory is now page-aligned, so size == 0 should work */
	/* mu_assert("function attempted to run with bad arguments (invalid size)", LM_AllocMemory(0, LM_PROT_NONE) == LM_ADDRESS_BAD); */

	mu_assert("function attempted to run with bad arguments (invalid prot)", LM_AllocMemory(ALLOCSIZE, BADPROT) == LM_ADDRESS_BAD);
	
	return NULL;
}

char *test_LM_ProtMemory(lm_address_t *palloc)
{
	lm_prot_t oldprot = LM_PROT_NONE;

	mu_assert("failed to change protection of memory", LM_ProtMemory(*palloc, ALLOCSIZE, LM_PROT_RW, &oldprot) == LM_TRUE);
	printf("<OLDPROT: %d> ", oldprot);
	fflush(stdout);
	mu_assert("old protection does not match its real value", oldprot == ALLOCPROT);
	mu_assert("failed to restore old protection of memory", LM_ProtMemory(*palloc, ALLOCSIZE, oldprot, LM_NULLPTR) == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid address)", LM_ProtMemory(LM_ADDRESS_BAD, ALLOCSIZE, LM_PROT_XR, LM_NULLPTR) == LM_FALSE);

	/* NOTE: LM_ProtMemory is now page-aligned, so size == 0 should work */
	/* mu_assert("function attempted to run with bad arguments (invalid size)", LM_ProtMemory(*palloc, 0, LM_PROT_XR, LM_NULLPTR) == LM_FALSE); */

	mu_assert("function attempted to run with bad arguments (invalid prot)", LM_ProtMemory(*palloc, ALLOCSIZE, BADPROT, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_FreeMemory(lm_address_t *palloc)
{
	mu_assert("failed to deallocate memory", LM_FreeMemory(*palloc, ALLOCSIZE) == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid alloc)", LM_FreeMemory(LM_ADDRESS_BAD, ALLOCSIZE) == LM_FALSE);

	return NULL;
}

char *test_LM_ReadMemory(void *arg)
{
	char buf[] = { 'A', 'B', 'C', 'D' };
	lm_byte_t buf_copy[sizeof(buf)] = { 0 };

	mu_assert("failed to read buffer into copy buffer", LM_ReadMemory((lm_address_t)buf, buf_copy, sizeof(buf_copy)) == sizeof(buf_copy));
	mu_assert("copy buffer does not match original buffer", memcmp(buf, buf_copy, sizeof(buf_copy)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid src)", LM_ReadMemory(LM_ADDRESS_BAD, buf_copy, sizeof(buf_copy)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid dst)", LM_ReadMemory((lm_address_t)buf, LM_NULLPTR, sizeof(buf_copy)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_ReadMemory((lm_address_t)buf, buf_copy, 0) == 0);
	
	return NULL;
}

char *test_LM_WriteMemory(void *arg)
{
	int number = 0;
	int new_number = 1337;

	mu_assert("failed to read buffer into copy buffer", LM_WriteMemory((lm_address_t)&number, (lm_bytearray_t)&new_number, sizeof(new_number)) == sizeof(new_number));
	mu_assert("written buffer does not match src buffer", number == new_number);
	mu_assert("function attempted to run with bad arguments (invalid dst)", LM_WriteMemory(LM_ADDRESS_BAD, (lm_bytearray_t)&new_number, sizeof(new_number)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid src)", LM_WriteMemory((lm_address_t)&number, LM_NULLPTR, sizeof(new_number)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_WriteMemory((lm_address_t)&number, (lm_bytearray_t)&new_number, 0) == 0);
	
	return NULL;
}

struct _ptrscan_layer2 {
	char pad[0x10];
	int player_health;
} static pointer_scan_layer2 = { { 0 }, 42 };

struct _ptrscan_layer1 {
	char pad[0xA0];
	void *next_layer;
} static pointer_scan_layer1 = { { 0 }, (void *)&pointer_scan_layer2 };

struct _ptrscan_layer0 {
	void *next_layer;
} static pointer_scan_layer0 = { (void *)&pointer_scan_layer1 };

static int *player_health_ptr = &pointer_scan_layer2.player_health;

static lm_address_t deep_ptr_offsets[] = { 0xA0, 0x10 };

static lm_size_t deep_ptr_noffsets = sizeof(deep_ptr_offsets) / sizeof(deep_ptr_offsets[0]);

char *test_LM_DeepPointer(void *arg)
{
	lm_address_t *offsets = deep_ptr_offsets;
	lm_size_t noffsets = deep_ptr_noffsets;
	int *deep_pointer = (int *)LM_DeepPointer((lm_address_t)&pointer_scan_layer0, offsets, noffsets);
	mu_assert("failed to resolve deep pointer", deep_pointer != (int *)LM_ADDRESS_BAD);
	mu_assert("deep pointer does not match expected address", deep_pointer == player_health_ptr);

	printf("<PLAYER HP: %d> ", *deep_pointer);
	fflush(stdout);
	
	mu_assert("deep pointer value is not the expected value", *deep_pointer == *player_health_ptr);
	
	mu_assert("function attempted to run with bad arguments (invalid base)", LM_DeepPointer(LM_ADDRESS_BAD, offsets, noffsets) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad arguments (invalid base)", LM_DeepPointer((lm_address_t)&pointer_scan_layer0, LM_NULLPTR, noffsets) == LM_ADDRESS_BAD);
	
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

	/* NOTE: LM_AllocMemory is now page-aligned, so size == 0 should work */
	/* mu_assert("function attempted to run with bad arguments (invalid size)", LM_AllocMemoryEx(ptargetproc, 0, LM_PROT_XRW) == LM_ADDRESS_BAD); */
	mu_assert("function attempted to run with bad arguments (invalid prot)", LM_AllocMemoryEx(ptargetproc, ALLOCSIZE, BADPROT) == LM_ADDRESS_BAD);

	return NULL;
}

char *test_LM_ProtMemoryEx(struct memory_args *arg)
{
	lm_process_t *ptargetproc = arg->ptargetproc;
	lm_address_t *palloc = arg->palloc;
	lm_prot_t oldprot = LM_PROT_NONE;

	mu_assert("failed to change protection of memory", LM_ProtMemoryEx(ptargetproc, *palloc, ALLOCSIZE, LM_PROT_RW, &oldprot) == LM_TRUE);
	mu_assert("old protection does not match its real value", oldprot == ALLOCPROT);
	mu_assert("failed to restore old protection of memory", LM_ProtMemoryEx(ptargetproc, *palloc, ALLOCSIZE, oldprot, LM_NULLPTR) == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_ProtMemoryEx(LM_NULLPTR, *palloc, ALLOCSIZE, LM_PROT_XR, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid address)", LM_ProtMemoryEx(ptargetproc, LM_ADDRESS_BAD, ALLOCSIZE, LM_PROT_XR, LM_NULLPTR) == LM_FALSE);

	/* NOTE: LM_ProtMemoryEx is now page-aligned, so size == 0 should work */
	/* mu_assert("function attempted to run with bad arguments (invalid size)", LM_ProtMemoryEx(ptargetproc, *palloc, 0, LM_PROT_XR, LM_NULLPTR) == LM_FALSE); */

	mu_assert("function attempted to run with bad arguments (invalid prot)", LM_ProtMemoryEx(ptargetproc, *palloc, ALLOCSIZE, BADPROT, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_WriteMemoryEx(struct memory_args *arg)
{
	lm_process_t *ptargetproc = arg->ptargetproc;
	lm_address_t *palloc = arg->palloc;
	uint32_t number = 1337;

	mu_assert("failed to write memory", LM_WriteMemoryEx(ptargetproc, *palloc, (lm_bytearray_t)&number, sizeof(number)) == sizeof(number));
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_WriteMemoryEx(LM_NULLPTR, *palloc, (lm_bytearray_t)&number, sizeof(number)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid dst)", LM_WriteMemoryEx(ptargetproc, LM_ADDRESS_BAD, (lm_bytearray_t)&number, sizeof(number)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid src)", LM_WriteMemoryEx(ptargetproc, *palloc, LM_NULLPTR, sizeof(number)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_WriteMemoryEx(ptargetproc, *palloc, (lm_bytearray_t)&number, 0) == 0);
	
	return NULL;
}

char *test_LM_SetMemoryEx(struct memory_args *arg)
{
	lm_process_t *ptargetproc = arg->ptargetproc;
	lm_address_t *palloc = arg->palloc;
	lm_address_t addr = *palloc + sizeof(uint32_t);
	lm_byte_t new_bytes = 0xFF;
	
	mu_assert("failed to set memory", LM_SetMemoryEx(ptargetproc, addr, 0xFF, sizeof(uint32_t)) == sizeof(uint32_t));
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_SetMemoryEx(LM_NULLPTR, addr, new_bytes, sizeof(uint32_t)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid dst)", LM_SetMemoryEx(ptargetproc, LM_ADDRESS_BAD, new_bytes, sizeof(uint32_t)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_SetMemoryEx(ptargetproc, addr, new_bytes, 0) == 0);
	
	return NULL;
}

char *test_LM_ReadMemoryEx(struct memory_args *arg)
{
	lm_process_t *ptargetproc = arg->ptargetproc;
	lm_address_t *palloc = arg->palloc;
	uint32_t numbers[2];

	mu_assert("failed to read memory", LM_ReadMemoryEx(ptargetproc, *palloc, (lm_byte_t *)numbers, sizeof(numbers)) == sizeof(numbers));
	mu_assert("wrong value for read or write memory", numbers[0] == 1337);
	mu_assert("wrong value for write or set memory", numbers[1] == 0xFFFFFFFF);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_ReadMemoryEx(ptargetproc, LM_ADDRESS_BAD, (lm_byte_t *)numbers, sizeof(numbers)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid src)", LM_ReadMemoryEx(ptargetproc, LM_ADDRESS_BAD, (lm_byte_t *)numbers, sizeof(numbers)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid dst)", LM_ReadMemoryEx(ptargetproc, *palloc, LM_NULLPTR, sizeof(numbers)) == 0);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_ReadMemoryEx(ptargetproc, *palloc, (lm_byte_t *)numbers, 0) == 0);
	
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

char *test_LM_DeepPointerEx(struct memory_args *arg)
{
	lm_byte_t writebuf[sizeof(pointer_scan_layer0) + sizeof(pointer_scan_layer1) + sizeof(pointer_scan_layer2)];
	lm_address_t layer1addr = *arg->palloc + sizeof(pointer_scan_layer0);
	lm_address_t layer2addr = layer1addr + sizeof(pointer_scan_layer1);
	void **nextlayer0 = (void **)&writebuf[offsetof(struct _ptrscan_layer0, next_layer)];
	void **nextlayer1 = (void **)&writebuf[sizeof(pointer_scan_layer0) + offsetof(struct _ptrscan_layer1, next_layer)];
	lm_address_t expected_addr = *arg->palloc + sizeof(pointer_scan_layer0) + sizeof(pointer_scan_layer1) + offsetof(struct _ptrscan_layer2, player_health);
	
	memcpy(writebuf, &pointer_scan_layer0, sizeof(pointer_scan_layer0));
	memcpy(&writebuf[sizeof(pointer_scan_layer0)], &pointer_scan_layer1, sizeof(pointer_scan_layer1));
	memcpy(&writebuf[sizeof(pointer_scan_layer0) + sizeof(pointer_scan_layer1)], &pointer_scan_layer2, sizeof(pointer_scan_layer2));
	*nextlayer0 = (void *)layer1addr;
	*nextlayer1 = (void *)layer2addr;

	mu_assert("failed to write pointer scan mock to target process", LM_WriteMemoryEx(arg->ptargetproc, *arg->palloc, writebuf, sizeof(writebuf)) == sizeof(writebuf));

	lm_address_t *offsets = deep_ptr_offsets;
	lm_size_t noffsets = deep_ptr_noffsets;
	lm_address_t deep_pointer = LM_DeepPointerEx(arg->ptargetproc, *arg->palloc, offsets, noffsets);

	mu_assert("deep pointer does not match expected address", deep_pointer == expected_addr);

	int health = 0;
	mu_assert("failed to read deep pointer value", LM_ReadMemoryEx(arg->ptargetproc, deep_pointer, (lm_byte_t *)&health, sizeof(health)) == sizeof(health));

	printf("<PLAYER HP: %d> ", health);
	fflush(stdout);
	
	mu_assert("deep pointer value does not match expected value", health == pointer_scan_layer2.player_health);
	
	return NULL;
}
