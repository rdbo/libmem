#include "arch.h"
#include <libmem/libmem.h>
#include <stdio.h>
#include <memory.h>

lm_arch_t
get_architecture()
{
	return LM_GetBits() == 64 ? LM_ARCH_X64 : LM_ARCH_X86;
}

lm_size_t
generate_hook_payload(lm_address_t from, lm_address_t to, lm_size_t bits, lm_byte_t **payload_out)
{
	lm_byte_t *code = NULL;
	lm_byte_t jump32[] = { 0xE9, 0x0, 0x0, 0x0, 0x0 }; /* jmp <rel addr> */
	lm_byte_t jump64[] = {
		0xFF, 0x25, 0x0, 0x0, 0x0, 0x0, /* jmp [rip] */
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* <abs addr> */
	};
	lm_byte_t *payload;
	lm_size_t size = 0;
	lm_address_t relative_addr;

	relative_addr = to - from - sizeof(jump32);

	if (bits == 64 && ((int64_t)relative_addr < (int64_t)0xFFFFFFFF80000000) || (int64_t)relative_addr > (int64_t)0x7FFFFFFF) {
		size = sizeof(jump64);
		payload = (lm_byte_t *)jump64;
		*(uint64_t *)(&jump64[6]) = (uint64_t)to;
	} else {
		size = sizeof(jump32);
		payload = (lm_byte_t *)jump32;
		*(uint32_t *)(&jump32[1]) = (uint32_t)relative_addr;
	}

	code = malloc(size);
	if (!code)
		return 0;

	memcpy(code, payload, size);
	*payload_out = code;

	return size;
}

lm_size_t
generate_no_ops(lm_byte_t *buf, lm_size_t size)
{
	memset(buf, 0x90, size);
	return size;
}
