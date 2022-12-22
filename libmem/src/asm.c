#include "internal.h"
#include <capstone/capstone.h>
#include <keystone/keystone.h>

LM_API lm_bool_t
LM_Assemble(lm_cstring_t code, lm_arch_t arch, lm_size_t bits, lm_inst_t *inst)
{
	lm_bool_t ret = LM_FALSE;
	ks_engine *ks;
	ks_arch ksarch;
	ks_mode ksmode;
	unsigned char *encode;
	size_t size;
	size_t count;

	LM_ASSERT(code != LM_NULLPTR && inst != LM_NULLPTR);

	switch (arch) {
	case LM_ARCH_X86: ksarch = KS_ARCH_X86; break;
	case LM_ARCH_ARM: ksarch = KS_ARCH_ARM; break;
	default: return ret;
	}

	switch (bits) {
	case 32: ksmode = KS_MODE_32; break;
	case 64: ksmode = KS_MODE_64; break;
	default: return ret;
	}

	if (ks_open(ksarch, ksmode, &ks) != KS_ERR_OK)
		return ret;

	ks_asm(ks, code, 0, &encode, &size, &count);
	if (size <= 0 || size > LM_INST_SIZE)
		goto CLEAN_EXIT;

	inst->size = size;
	memcpy((void *)inst->bytes, (void *)encode, size);

	ks_free(encode);
	ret = LM_TRUE;
CLEAN_EXIT:
	ks_close(ks);
	return ret;
}

/********************************/

LM_API lm_bool_t
LM_Disassemble(lm_address_t code, lm_arch_t arch, lm_size_t bits, lm_inst_t *inst)
{
	lm_bool_t ret = LM_FALSE;
	csh cshandle;
	cs_insn *csinsn;
	cs_arch csarch;
	cs_mode csmode;
	size_t count;

	LM_ASSERT(code != LM_ADDRESS_BAD && inst != LM_NULLPTR);

	switch (arch) {
	case LM_ARCH_X86: csarch = CS_ARCH_X86; break;
	case LM_ARCH_ARM: csarch = CS_ARCH_ARM; break;
	}

	switch (bits) {
	case 32: csmode = CS_MODE_32; break;
	case 64: csmode = CS_MODE_64; break;
	}

	if (cs_open(csarch, csmode, &cshandle) != CS_ERR_OK)
		return LM_FALSE;

	count = cs_disasm(cshandle, code, LM_INST_SIZE, 0, 1, &csinsn);
	if (count <= 0)
		goto CLEAN_EXIT;

	memcpy((void *)inst, (void *)&csinsn[0], sizeof(lm_inst_t));

	cs_free(csinsn, count);
	ret = LM_TRUE;
CLEAN_EXIT:
	cs_close(&cshandle);
	return ret;
}

/********************************/

LM_API lm_size_t
LM_CodeLength(lm_address_t code, lm_size_t minlength)
{
	lm_size_t length;
	lm_inst_t inst;

	LM_ASSERT(code != LM_ADDRESS_BAD && minlength > 0);

	for (length = 0; length < minlength; code = (lm_address_t)LM_OFFSET(code, length)) {
		if (LM_Disassemble(code, LM_ARCH, LM_BITS, &inst) == LM_FALSE)
			return 0;
		length += inst.size;
	}

	return length;
}
