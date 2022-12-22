#include "internal.h"

#if LM_OS == LM_OS_WIN
#include <LIEF/PE.hpp>

using namespace LIEF::PE;

LM_PRIVATE lm_bool_t
_LM_EnumPeSyms(lm_size_t    bits,
	       lm_address_t modbase,
	       lm_bool_t  (*callback)(lm_cstring_t symbol,
				      lm_address_t addr,
				      lm_void_t   *arg),
	       lm_void_t *arg)
{
	/* TODO: Implement */
	return LM_FALSE;

	/*
	if (!is_pe(modpath))
		return LM_FALSE;

	std::unique_ptr<const PE::Binary> binary_pe = PE::Parser::parse(PE_PATH);

	for (const PE::ExportEntry &symbol : binary_pe->get_export().entries()) {
	}
	return LM_TRUE;
	*/
}
#else
#include <LIEF/ELF.hpp>

using namespace LIEF::ELF;

LM_PRIVATE lm_size_t
_LM_GetElfBits(lm_tchar_t *path)
{
	lm_size_t bits = 0;
	int fd;
	unsigned char elf_num;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return bits;

	/*
	 * ELF Magic:
	 * 32 bits -> 0x7F, E, L, F, 1
	 * 64 bits -> 0x7F, E, L, F, 2
	 */

	lseek(fd, (int)IDENTITY::EI_MAG3 + 1, SEEK_SET);
	if (read(fd, &elf_num, sizeof(elf_num)) > 0 &&
	    (elf_num == 1 || elf_num == 2))
		bits = elf_num * 32;

	close(fd);

	return bits;
}

LM_PRIVATE lm_bool_t
_LM_EnumElfSyms(lm_module_t mod,
		lm_tchar_t *modpath,
		lm_bool_t (*callback)(lm_cstring_t symbol,
				      lm_address_t addr,
				      lm_void_t   *arg),
		lm_void_t  *arg)
{
	lm_cstring_t symstr;
        lm_address_t addr;
        lm_address_t base = (lm_address_t)0; /* base address for symbol offset */
        std::unique_ptr<const Binary> binary;

        LM_ASSERT(modpath != LM_NULLPTR && callback != LM_NULLPTR);

        if (!is_elf(modpath))
                return LM_FALSE;

        binary = Parser::parse(modpath);

        if (binary->header().file_type() != E_TYPE::ET_EXEC)
                base = mod.base;

        for (const Symbol &symbol : binary->exported_symbols()) {
                symstr = (lm_cstring_t)symbol.name().c_str();
                addr = (lm_address_t)(&((lm_byte_t *)base)[symbol.value()]);
                if (!callback(symstr, addr, arg))
                        break;
        }

        return LM_TRUE;
}
#endif

