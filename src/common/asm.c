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

#include <libmem/libmem.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <memory.h>
#include "arch/arch.h"

/********************************/

LM_API lm_arch_t LM_CALL
LM_GetArchitecture()
{
	return get_architecture();
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_Assemble(lm_string_t code,
	    lm_inst_t  *instruction_out)
{
	lm_bool_t ret = LM_FALSE;
	lm_byte_t *payload;

	if (!code || !instruction_out)
		return ret;

	if (!LM_AssembleEx(code, LM_GetArchitecture(), 0, &payload))
		return ret;

	ret = LM_Disassemble((lm_address_t)payload, instruction_out);

	LM_FreePayload(payload);

	return ret;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_AssembleEx(lm_string_t  code,
              lm_arch_t    arch,
	      lm_address_t runtime_address,
	      lm_byte_t  **payload_out)
{
	ks_engine *ks;
	ks_arch ksarch = 0;
	ks_mode ksmode = 0;
	lm_size_t size = 0;
	size_t asmsize;
	size_t count;

	if (!code || arch >= LM_ARCH_MAX || !payload_out)
		return size;

	switch (arch) {
	/* ARM */
	case LM_ARCH_ARMV7:
		ksarch = KS_ARCH_ARM;
		ksmode = KS_MODE_LITTLE_ENDIAN | KS_MODE_ARM;
		break;
	case LM_ARCH_ARMV8:
		ksarch = KS_ARCH_ARM;
		ksmode = KS_MODE_LITTLE_ENDIAN | KS_MODE_ARM | KS_MODE_V8;
		break;
	case LM_ARCH_THUMBV7:
		ksarch = KS_ARCH_ARM;
		ksmode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB;
		break;
	case LM_ARCH_THUMBV8:
		ksarch = KS_ARCH_ARM;
		ksmode = KS_MODE_LITTLE_ENDIAN | KS_MODE_THUMB | KS_MODE_V8;
		break;

	case LM_ARCH_ARMV7EB:
		ksarch = KS_ARCH_ARM;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_ARM;
		break;
	case LM_ARCH_THUMBV7EB:
		ksarch = KS_ARCH_ARM;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_THUMB;
		break;
	case LM_ARCH_ARMV8EB:
		ksarch = KS_ARCH_ARM;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_ARM | KS_MODE_V8;
		break;
	case LM_ARCH_THUMBV8EB:
		ksarch = KS_ARCH_ARM;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_THUMB | KS_MODE_V8;
		break;

	case LM_ARCH_AARCH64:
		ksarch = KS_ARCH_ARM64;
		ksmode = KS_MODE_LITTLE_ENDIAN;
		break;
	/* MIPS */
	case LM_ARCH_MIPS:
		ksarch = KS_ARCH_MIPS;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_MIPS32;
		break;
	case LM_ARCH_MIPS64:
		ksarch = KS_ARCH_MIPS;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_MIPS64;
		break;
	case LM_ARCH_MIPSEL:
		ksarch = KS_ARCH_MIPS;
		ksmode = KS_MODE_LITTLE_ENDIAN | KS_MODE_MIPS32;
		break;
	case LM_ARCH_MIPSEL64:
		ksarch = KS_ARCH_MIPS;
		ksmode = KS_MODE_LITTLE_ENDIAN | KS_MODE_MIPS64;
		break;
	/* X86 */
	case LM_ARCH_X86_16:
		ksarch = KS_ARCH_X86;
		ksmode = KS_MODE_16;
		break;
	case LM_ARCH_X86:
		ksarch = KS_ARCH_X86;
		ksmode = KS_MODE_32;
		break;
	case LM_ARCH_X64:
		ksarch = KS_ARCH_X86;
		ksmode = KS_MODE_64;
		break;
	/* PowerPC */
	case LM_ARCH_PPC32:
		ksarch = KS_ARCH_PPC;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_PPC32;
		break;
	case LM_ARCH_PPC64:
		ksarch = KS_ARCH_PPC;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_PPC64;
		break;
	case LM_ARCH_PPC64LE:
		ksarch = KS_ARCH_PPC;
		ksmode = KS_MODE_LITTLE_ENDIAN | KS_MODE_PPC32;
		break;

	/* SPARC */
	case LM_ARCH_SPARC:
		ksarch = KS_ARCH_SPARC;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_SPARC32;
		break;
	case LM_ARCH_SPARC64:
		ksarch = KS_ARCH_SPARC;
		ksmode = KS_MODE_BIG_ENDIAN | KS_MODE_SPARC64;
		break;
	case LM_ARCH_SPARCEL:
		ksarch = KS_ARCH_SPARC;
		ksmode = KS_MODE_LITTLE_ENDIAN | KS_MODE_SPARC32;
		break;
	/* SystemZ */
	case LM_ARCH_SYSZ:
		ksarch = KS_ARCH_SYSTEMZ;
		ksmode = 0;
		break;
	}

	if (ks_open(ksarch, ksmode, &ks) != KS_ERR_OK)
		return size;

	if (ks_asm(ks, code, runtime_address, payload_out, &asmsize, &count))
		goto CLOSE_EXIT;

	size = (lm_size_t)asmsize;
CLOSE_EXIT:
	ks_close(ks);
	return size;
}

/********************************/

LM_API lm_void_t LM_CALL
LM_FreePayload(lm_byte_t *payload)
{
	ks_free(payload);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_Disassemble(lm_address_t machine_code,
	       lm_inst_t   *instruction_out)
{
	lm_inst_t *insts;
	
	if (!machine_code || !instruction_out)
		return LM_FALSE;

	if (LM_DisassembleEx(machine_code, LM_GetArchitecture(), LM_INST_MAX, 1, machine_code, &insts) == 0)
		return LM_FALSE;

	*instruction_out = *insts;

	LM_FreeInstructions(insts);

	return LM_TRUE;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_DisassembleEx(lm_address_t machine_code,
		 lm_arch_t    arch,
		 lm_size_t    max_size,
		 lm_size_t    instruction_count,
		 lm_address_t runtime_address,
		 lm_inst_t  **instructions_out)
{
	lm_size_t inst_count = 0;
	csh cshandle;
	cs_arch csarch;
	cs_mode csmode;
	cs_insn *csinsts;
	lm_inst_t *insts;
	lm_size_t i;

	if (machine_code == LM_ADDRESS_BAD || arch >= LM_ARCH_MAX || (max_size == 0 && instruction_count == 0) || !instructions_out)
		return inst_count;

	switch (arch) {
	/* ARM */
	case LM_ARCH_ARMV7:
		csarch = CS_ARCH_ARM;
		csmode = CS_MODE_LITTLE_ENDIAN | CS_MODE_ARM;
		break;
	case LM_ARCH_ARMV8:
		csarch = CS_ARCH_ARM;
		csmode = CS_MODE_LITTLE_ENDIAN | CS_MODE_ARM | CS_MODE_V8;
		break;
	case LM_ARCH_THUMBV7:
		csarch = CS_ARCH_ARM;
		csmode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB;
		break;
	case LM_ARCH_THUMBV8:
		csarch = CS_ARCH_ARM;
		csmode = CS_MODE_LITTLE_ENDIAN | CS_MODE_THUMB | CS_MODE_V8;
		break;

	case LM_ARCH_ARMV7EB:
		csarch = CS_ARCH_ARM;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_ARM;
		break;
	case LM_ARCH_THUMBV7EB:
		csarch = CS_ARCH_ARM;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_THUMB;
		break;
	case LM_ARCH_ARMV8EB:
		csarch = CS_ARCH_ARM;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_ARM | CS_MODE_V8;
		break;
	case LM_ARCH_THUMBV8EB:
		csarch = CS_ARCH_ARM;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_THUMB | CS_MODE_V8;
		break;

	case LM_ARCH_AARCH64:
		csarch = CS_ARCH_ARM64;
		csmode = CS_MODE_LITTLE_ENDIAN;
		break;
	/* MIPS */
	case LM_ARCH_MIPS:
		csarch = CS_ARCH_MIPS;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_MIPS32;
		break;
	case LM_ARCH_MIPS64:
		csarch = CS_ARCH_MIPS;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_MIPS64;
		break;
	case LM_ARCH_MIPSEL:
		csarch = CS_ARCH_MIPS;
		csmode = CS_MODE_LITTLE_ENDIAN | CS_MODE_MIPS32;
		break;
	case LM_ARCH_MIPSEL64:
		csarch = CS_ARCH_MIPS;
		csmode = CS_MODE_LITTLE_ENDIAN | CS_MODE_MIPS64;
		break;
	/* X86 */
	case LM_ARCH_X86_16:
		csarch = CS_ARCH_X86;
		csmode = CS_MODE_16;
		break;
	case LM_ARCH_X86:
		csarch = CS_ARCH_X86;
		csmode = CS_MODE_32;
		break;
	case LM_ARCH_X64:
		csarch = CS_ARCH_X86;
		csmode = CS_MODE_64;
		break;
	/* PowerPC */
	case LM_ARCH_PPC32:
		csarch = CS_ARCH_PPC;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_32;
		break;
	case LM_ARCH_PPC64:
		csarch = CS_ARCH_PPC;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_64;
		break;
	case LM_ARCH_PPC64LE:
		csarch = CS_ARCH_PPC;
		csmode = CS_MODE_LITTLE_ENDIAN | CS_MODE_32;
		break;

	/* SPARC */
	case LM_ARCH_SPARC:
		csarch = CS_ARCH_SPARC;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_32;
		break;
	case LM_ARCH_SPARC64:
		csarch = CS_ARCH_SPARC;
		csmode = CS_MODE_BIG_ENDIAN | CS_MODE_64;
		break;
	case LM_ARCH_SPARCEL:
		csarch = CS_ARCH_SPARC;
		csmode = CS_MODE_LITTLE_ENDIAN | CS_MODE_32;
		break;
	/* SystemZ */
	case LM_ARCH_SYSZ:
		csarch = CS_ARCH_SYSZ;
		csmode = 0;
		break;
	}

	if (cs_open(csarch, csmode, &cshandle) != CS_ERR_OK)
		return inst_count;

	inst_count = cs_disasm(cshandle, (uint8_t *)machine_code, max_size, runtime_address, instruction_count, &csinsts);
	if (inst_count == 0)
		goto CLOSE_EXIT;

	insts = calloc(inst_count, sizeof(lm_inst_t));
	if (!insts)
		goto CLOSE_EXIT;

	for (i = 0; i < inst_count; ++i) {
		insts[i].address = csinsts[i].address;
		insts[i].size = csinsts[i].size;
		memcpy(insts[i].bytes, csinsts[i].bytes, sizeof(insts[i].bytes));
		memcpy(insts[i].mnemonic, csinsts[i].mnemonic, sizeof(insts[i].mnemonic));
		memcpy(insts[i].op_str, csinsts[i].op_str, sizeof(insts[i].op_str));
	}
	cs_free(csinsts, inst_count);

	*instructions_out = insts;
CLOSE_EXIT:
	cs_close(&cshandle);
	return inst_count;
}

/********************************/

LM_API lm_void_t LM_CALL
LM_FreeInstructions(lm_inst_t *instructions)
{
	free(instructions);
}

/********************************/

LM_API lm_size_t LM_CALL
LM_CodeLength(lm_address_t machine_code,
	      lm_size_t    min_length)
{
	lm_size_t length = 0;
	lm_inst_t inst;

	if (machine_code == LM_ADDRESS_BAD)
		return 0;

	for (; length < min_length; length += inst.size) {
		if (LM_Disassemble(machine_code, &inst) == LM_FALSE)
			return 0;
		machine_code += inst.size;
	}

	return length;
}

/********************************/

static lm_arch_t
get_process_arch(const lm_process_t *process)
{
	lm_arch_t current_arch = LM_GetArchitecture();
	lm_arch_t process_arch = current_arch;
	switch (current_arch) {
	case LM_ARCH_X86_16:
	case LM_ARCH_X86:
	case LM_ARCH_X64:
		if (process->bits == 64) {
			process_arch = LM_ARCH_X64;
		} else {
			process_arch = LM_ARCH_X86;
		}
		break;
	}

	return process_arch;
}

LM_API lm_size_t LM_CALL
LM_CodeLengthEx(const lm_process_t *process,
		lm_address_t        machine_code,
		lm_size_t           min_length)
{
	lm_size_t length = 0;
	lm_inst_t *insts;
	lm_byte_t codebuf[LM_INST_MAX];

	if (!process || machine_code == LM_ADDRESS_BAD)
		return 0;

	for (; length < min_length; length += insts[0].size, LM_FreeInstructions(insts)) {
		if (LM_ReadMemoryEx(process, machine_code, codebuf, sizeof(codebuf)) == 0)
			return 0;

		if (LM_DisassembleEx((lm_address_t)codebuf, get_process_arch(process), LM_INST_MAX, 1, 0, &insts) == 0)
			return 0;

		machine_code += insts[0].size;
	}

	return length;
}
