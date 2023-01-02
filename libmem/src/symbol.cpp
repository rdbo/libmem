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
#include <libmem.h>

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

LM_PRIVATE lm_bool_t
_LM_EnumSymbols(lm_module_t *pmod,
		lm_bool_t  (*callback)(lm_cstring_t symbol,
				       lm_address_t addr,
				       lm_void_t   *arg),
		lm_void_t   *arg)
{
	return _LM_EnumPeSyms(LM_BITS, pmod->base, callback, arg);
}
#else
#include <LIEF/ELF.hpp>

using namespace LIEF::ELF;

LM_PRIVATE lm_bool_t
_LM_EnumElfSyms(lm_module_t *pmod,
		lm_tchar_t  *modpath,
		lm_bool_t  (*callback)(lm_cstring_t symbol,
				       lm_address_t addr,
				       lm_void_t   *arg),
		lm_void_t   *arg)
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
                base = pmod->base;

        for (const Symbol &symbol : binary->exported_symbols()) {
                symstr = (lm_cstring_t)symbol.name().c_str();
                addr = (lm_address_t)(&((lm_byte_t *)base)[symbol.value()]);
                if (!callback(symstr, addr, arg))
                        break;
        }

        return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumSymbols(lm_module_t *pmod,
		lm_bool_t  (*callback)(lm_cstring_t symbol,
				       lm_address_t addr,
				       lm_void_t   *arg),
		lm_void_t   *arg)
{
	lm_process_t proc;

	if (!LM_GetProcess(&proc))
		return LM_FALSE;

	return LM_EnumSymbolsEx(&proc, pmod, callback, arg);
}
#endif

LM_API lm_bool_t
LM_EnumSymbols(lm_module_t *pmod,
	       lm_bool_t  (*callback)(lm_cstring_t symbol,
				      lm_address_t addr,
				      lm_void_t   *arg),
	       lm_void_t   *arg)
{
	LM_ASSERT(pmod != LM_NULLPTR && callback != LM_NULLPTR);

	return _LM_EnumSymbols(pmod, callback, arg);
}
/********************************/
#if LM_OS == LM_OS_WIN
LM_API lm_bool_t
_LM_EnumSymbolsEx(lm_process_t *pproc,
		  lm_module_t  *pmod,
	          lm_bool_t   (*callback)(lm_cstring_t symbol,
					  lm_address_t addr,
					  lm_void_t   *arg),
		  lm_void_t    *arg)
{
	lm_bool_t    ret = LM_FALSE;
	lm_address_t alloc;

	alloc = LM_AllocMemory(LM_PROT_RW, mod.size);
	if (alloc == LM_ADDRESS_BAD)
		return ret;
		
	if (LM_ReadMemoryEx(pproc, mod.base, (lm_byte_t *)alloc, mod.size))
		ret = _LM_EnumPeSyms(pproc->bits, alloc, callback, arg);

	LM_FreeMemory(alloc, mod.size);

	return ret;
}
#else
LM_API lm_bool_t
_LM_EnumSymbolsEx(lm_process_t *pproc,
		  lm_module_t  *pmod,
	          lm_bool_t   (*callback)(lm_cstring_t symbol,
					  lm_address_t addr,
					  lm_void_t   *arg),
		  lm_void_t    *arg)
{
	return _LM_EnumElfSyms(pmod, pmod->path, callback, arg);
}
#endif
LM_API lm_bool_t
LM_EnumSymbolsEx(lm_process_t *pproc,
		 lm_module_t  *pmod,
	         lm_bool_t   (*callback)(lm_cstring_t symbol,
					 lm_address_t addr,
					 lm_void_t   *arg),
		 lm_void_t    *arg)
{
	LM_ASSERT(pproc != LM_NULLPTR &&
		  pmod != LM_NULLPTR &&
		  callback != LM_NULLPTR);

	return _LM_EnumSymbolsEx(pproc, pmod, callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_address_t
_LM_FindSymbol(lm_module_t *pmod,
	       lm_cstring_t symstr)
{
	lm_address_t symaddr = LM_ADDRESS_BAD;
	HMODULE      hModule;
	PVOID        procaddr;

	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
			  (LPTSTR)pmod->base, &hModule);		
	if (!hModule)
		return symaddr;

	procaddr = (PVOID)GetProcAddress(hModule, symstr);
	if (!procaddr)
		return symaddr;

	symaddr = (lm_address_t)procaddr;

	return symaddr;
}
#else
LM_PRIVATE lm_address_t
_LM_FindSymbol(lm_module_t *pmod,
	       lm_cstring_t symstr)
{
	lm_process_t proc;

	if (!LM_GetProcess(&proc))
		return LM_ADDRESS_BAD;

	return LM_FindSymbolEx(&proc, pmod, symstr);
}
#endif

LM_API lm_address_t
LM_FindSymbol(lm_module_t *pmod,
	     lm_cstring_t  symstr)
{
	LM_ASSERT(pmod != LM_NULLPTR && symstr != LM_NULLPTR);

	return _LM_FindSymbol(pmod, symstr);
}

/********************************/

typedef struct {
	lm_cstring_t symbol;
	lm_address_t addr;
} _lm_get_symbol_t;

LM_PRIVATE lm_bool_t
_LM_FindSymbolExCallback(lm_cstring_t symbol,
			 lm_address_t addr,
			 lm_void_t   *arg)
{
	_lm_get_symbol_t *parg = (_lm_get_symbol_t *)arg;

	if (!LM_STRCMP(symbol, parg->symbol)) {
		parg->addr = addr;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_address_t
LM_FindSymbolEx(lm_process_t *pproc,
		lm_module_t  *pmod,
		lm_cstring_t  symstr)
{
	_lm_get_symbol_t arg;

	LM_ASSERT(pproc != LM_NULLPTR &&
		  pmod != LM_NULLPTR &&
		  symstr != LM_NULLPTR);

	arg.symbol = symstr;
	arg.addr   = LM_ADDRESS_BAD;

	LM_EnumSymbolsEx(pproc, pmod,
			 _LM_FindSymbolExCallback, (lm_void_t *)&arg);

	return arg.addr;
}

