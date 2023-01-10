/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2022    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define LM_FORCE_LANG_CPP
#include <libmem/libmem.h>

#if LM_OS == LM_OS_WIN
#include <LIEF/PE.hpp>

using namespace LIEF::PE;

LM_PRIVATE lm_bool_t
_LM_EnumPeSyms(lm_module_t *pmod,
	       lm_bool_t  (*callback)(lm_symbol_t *psymbol,
				      lm_void_t   *arg),
	       lm_void_t *arg)
{
	lm_symbol_t sym;
	std::unique_ptr<const Binary> binary;

	if (!is_pe(pmod->path))
		return LM_FALSE;

	binary = Parser::parse(pmod->path);

	for (const ExportEntry &symbol : binary->get_export().entries()) {
		sym.name = symbol.name().c_str();
		sym.address = LM_OFFSET(pmod->base, symbol.value());
		if (!callback(&sym, arg))
			break;
	}

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumSymbols(lm_module_t *pmod,
		lm_bool_t  (*callback)(lm_symbol_t *psymbol,
				       lm_void_t   *arg),
		lm_void_t   *arg)
{
	return _LM_EnumPeSyms(pmod, callback, arg);
}
#else
#include <elfio/elfio.hpp>

using namespace ELFIO;

LM_PRIVATE lm_bool_t
_LM_EnumElfSyms(lm_module_t *pmod,
		lm_bool_t  (*callback)(lm_symbol_t *psymbol,
				       lm_void_t   *arg),
		lm_void_t   *arg)
{
	lm_symbol_t sym;
	lm_address_t base = (lm_address_t)0; /* base address for symbol offset */
	elfio reader;

	if (!reader.load(pmod->path))
		return LM_FALSE;

	if (reader.get_type() != ET_EXEC)
		base = pmod->base;

	for (Elf_Half i = 0; i < reader.sections.size(); ++i) {
		section* psec =  reader.sections[i];
		if (psec->get_type() != SHT_SYMTAB)
			continue;

		const symbol_section_accessor symbols(reader, psec);
		for (unsigned int j = 0; j < symbols.get_symbols_num(); ++j) {
			std::string   name;
			Elf64_Addr    value;
			Elf_Xword     size;
			unsigned char bind;
			unsigned char type;
			Elf_Half      section_index;
			unsigned char other;
			lm_symbol_t   sym;

			symbols.get_symbol(
				j, name, value, size, bind, type,
				section_index, other
			);

			sym.name = (lm_cstring_t)name.c_str();
			sym.address = (lm_address_t)LM_OFFSET(base, value);
			if (!callback(&sym, arg))
				goto EXIT;
		}
	}

EXIT:
	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumSymbols(lm_module_t *pmod,
		lm_bool_t  (*callback)(lm_symbol_t *psymbol,
				       lm_void_t   *arg),
		lm_void_t   *arg)
{
	return _LM_EnumElfSyms(pmod, callback, arg);
}
#endif

LM_API lm_bool_t
LM_EnumSymbols(lm_module_t *pmod,
	       lm_bool_t  (*callback)(lm_symbol_t *psymbol,
				      lm_void_t   *arg),
	       lm_void_t   *arg)
{
	LM_ASSERT(pmod != LM_NULLPTR && callback);

	return _LM_EnumSymbols(pmod, callback, arg);
}
/********************************/

LM_PRIVATE lm_bool_t
_LM_FindSymbolAddressCallback(lm_symbol_t *psymbol,
			      lm_void_t   *arg)
{
	lm_symbol_t *parg = (lm_symbol_t *)arg;

	if (!LM_STRCMP(psymbol->name, parg->name)) {
		parg->address = psymbol->address;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_address_t
LM_FindSymbolAddress(lm_module_t  *pmod,
		     lm_cstring_t  name)
{
	lm_symbol_t arg;

	LM_ASSERT(pmod != LM_NULLPTR && name != LM_NULLPTR);

	arg.name = name;
	arg.address = LM_ADDRESS_BAD;

	LM_EnumSymbols(pmod, _LM_FindSymbolAddressCallback, (lm_void_t *)&arg);

	return arg.address;
}

