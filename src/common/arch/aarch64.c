/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2025    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "arch.h"
#include <libmem/libmem.h>
#include <stdio.h>
#include <memory.h>

lm_arch_t
get_architecture()
{
	// 32-bit mode for AArch64 will not be supported directly
	// as it is for x64. Compile for the specific ARM instruction
	// set that the target program is using for max compatibility.
	return LM_ARCH_AARCH64;
}

lm_size_t
get_max_hook_size()
{
	return 16;
}


lm_size_t
generate_hook_payload(lm_address_t from, lm_address_t to, lm_size_t bits, lm_byte_t **payload_out)
{
	lm_byte_t *code = NULL;
	lm_byte_t jump32[] = { 0x0, 0x0, 0x0, 0x14 }; /* B <rel_addr> */
	lm_byte_t jump64[] = {
		0x51, 0x00, 0x00, 0x58, /* LDR x17, #8 */
		0x20, 0x02, 0x5F, 0xD6, /* RET x17 */
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* <abs addr> */
	};
	lm_byte_t *payload;
	lm_size_t size = 0;
	lm_address_t relative_addr;

	relative_addr = (to - from /* - sizeof(jump32) */) / 4; // Branch offsets are multiples of 4

	// 26 bit address short jump
	if ((int64_t)relative_addr > 0x1FFFFFF || (int64_t)relative_addr < (int64_t)0xFFFFFFFFF4000000) {
		size = sizeof(jump64);
		payload = (lm_byte_t *)jump64;
		*(uint64_t *)(&jump64[8]) = (uint64_t)to;
	} else {
		uint32_t inst = *(uint32_t *)jump32;
		size = sizeof(jump32);
		payload = (lm_byte_t *)jump32;
		inst |= (relative_addr & 0x03FFFFFF);
		*(uint32_t *)jump32 = inst;
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
	size_t i;
	// Assure that the size is a multiple of 4
	if (size & 3 != 0)
		return 0;

	for (i = size; i >= 4; i -= 4) {
		*(uint32_t *)&buf[i - 4] = 0xD503201F;
	}

	return size;
}
