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

/********************************/

LM_API lm_arch_t LM_CALL
LM_GetArchitecture()
{
	return LM_ARCH_X86;
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

	if (!LM_AssembleEx(code, LM_GetArchitecture(), sizeof(void *), 0, &payload))
		return ret;

	ret = LM_Disassemble((lm_address_t)payload, instruction_out);

	LM_FreePayload(payload);

	return ret;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_AssembleEx(lm_string_t  code,
              lm_arch_t    arch,
	      lm_size_t    bits,
	      lm_address_t runtime_address,
	      lm_byte_t  **payload_out)
{
	ks_engine *ks;
	ks_arch ksarch;
	ks_mode ksmode;
	lm_size_t size = 0;
	size_t asmsize;
	size_t count;
	static const ks_arch arch_cvt_table[] = {
		KS_ARCH_ARM,
		KS_ARCH_ARM64,
		KS_ARCH_MIPS,
		KS_ARCH_X86,
		KS_ARCH_PPC,
		KS_ARCH_SPARC,
		KS_ARCH_SYSTEMZ,
		KS_ARCH_EVM,
	};

	if (!code || arch >= LM_ARCH_MAX || (bits != 32 && bits != 64) || !payload_out)
		return size;

	ksarch = arch_cvt_table[arch];

	if (bits == 64)
		ksmode = KS_MODE_64;
	else
		ksmode = KS_MODE_32;

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

	if (LM_DisassembleEx(machine_code, LM_GetArchitecture(), sizeof(void *), LM_INST_MAX, 1, 0, &insts) == 0)
		return LM_FALSE;

	*instruction_out = *insts;

	LM_FreeInstructions(insts);

	return LM_TRUE;
}

/********************************/

LM_API lm_size_t LM_CALL
LM_DisassembleEx(lm_address_t machine_code,
		 lm_arch_t    arch,
		 lm_size_t    bits,
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

	static const cs_arch arch_cvt_table[] = {
		CS_ARCH_ARM,
		CS_ARCH_ARM64,
		CS_ARCH_MIPS,
		CS_ARCH_X86,
		CS_ARCH_PPC,
		CS_ARCH_SPARC,
		CS_ARCH_SYSZ,
		CS_ARCH_EVM,
	};

	if (machine_code == LM_ADDRESS_BAD || arch >= LM_ARCH_MAX || (bits != 32 && bits != 64) || (max_size == 0 && instruction_count == 0) || !instructions_out)
		return inst_count;

	csarch = arch_cvt_table[arch];

	if (bits == 64)
		csmode = CS_MODE_64;
	else
		csmode = CS_MODE_32;

	if (!cs_open(csarch, csmode, &cshandle) != CS_ERR_OK)
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

LM_API lm_size_t LM_CALL
LM_CodeLengthEx(lm_process_t *process,
		lm_address_t  machine_code,
		lm_size_t     min_length)
{
	lm_size_t length = 0;
	lm_inst_t inst;
	lm_byte_t codebuf[LM_INST_MAX];

	if (!process || machine_code == LM_ADDRESS_BAD)
		return 0;

	for (; length < min_length; length += inst.size) {
		if (LM_ReadMemoryEx(process, machine_code, codebuf, sizeof(codebuf)) == 0)
			return 0;

		if (LM_Disassemble(codebuf, &inst) == LM_FALSE)
			return 0;

		machine_code += inst.size;
	}

	return length;
}
