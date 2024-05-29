/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
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

#ifndef ARCH_H
#define ARCH_H

#include <libmem/libmem.h>

lm_arch_t
get_architecture();

lm_size_t
generate_hook_payload(lm_address_t from, lm_address_t to, lm_size_t bits, lm_byte_t **payload_out);

lm_size_t
generate_no_ops(lm_byte_t *buf, lm_size_t size);

/* NOTE: This function does heavy assuptions about processes running in a different
 *       bitsize than the current process. More testing should be done to check if
 *       it actually holds. */
static inline lm_arch_t
get_architecture_from_bits(lm_size_t bits)
{
	lm_arch_t arch;
	lm_arch_t target_arch;

	arch = get_architecture();
	switch (arch) {
	case LM_ARCH_ARMV7:
	case LM_ARCH_AARCH64:
		if (bits == 64)
			target_arch = LM_ARCH_AARCH64;
		else
			target_arch = LM_ARCH_ARMV7;
		break;
	case LM_ARCH_ARMV7EB:
		if (bits == 64)
			target_arch = LM_ARCH_AARCH64;
		else
			target_arch = LM_ARCH_ARMV7EB;
		break;
	case LM_ARCH_X86_16:
	case LM_ARCH_X86:
	case LM_ARCH_X64:
		if (bits == 64)
			target_arch = LM_ARCH_X64;
		else
			target_arch = LM_ARCH_X86;
		break;
	case LM_ARCH_MIPS:
	case LM_ARCH_MIPS64:
		if (bits == 64)
			target_arch = LM_ARCH_MIPS64;
		else
			target_arch = LM_ARCH_MIPS;
		break;
	case LM_ARCH_MIPSEL:
	case LM_ARCH_MIPSEL64:
		if (bits == 64)
			target_arch = LM_ARCH_MIPSEL64;
		else
			target_arch = LM_ARCH_MIPSEL;
		break;
	case LM_ARCH_PPC32:
	case LM_ARCH_PPC64:
		if (bits == 64)
			target_arch = LM_ARCH_PPC32;
		else
			target_arch = LM_ARCH_PPC64;
	case LM_ARCH_SPARC:
	case LM_ARCH_SPARC64:
		if (bits == 64)
			target_arch = LM_ARCH_SPARC;
		else
			target_arch = LM_ARCH_SPARC64;
		break;
	default:
		target_arch = arch;
		break;
	}

	return target_arch;
}

#endif
