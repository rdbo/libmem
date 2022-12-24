#include "internal.h"

#if LM_OS == LM_OS_WIN
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
_LM_EnumSymbols(lm_module_t mod,
		lm_bool_t (*callback)(lm_cstring_t symbol,
				      lm_address_t addr,
				      lm_void_t   *arg),
		lm_void_t *arg)
{
	return _LM_EnumPeSyms(LM_GetProcessBits(), mod.base, callback, arg);
}
#else
using namespace LIEF::ELF;

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

LM_PRIVATE lm_bool_t
_LM_EnumSymbols(lm_module_t mod,
		lm_bool_t (*callback)(lm_cstring_t symbol,
				      lm_address_t addr,
				      lm_void_t   *arg),
		lm_void_t *arg)
{
	lm_bool_t    ret = LM_FALSE;
	lm_process_t proc;
	if (!LM_OpenProcess(&proc))
		return ret;

	ret = LM_EnumSymbolsEx(proc, mod, callback, arg);
	LM_CloseProcess(&proc);
	return ret;
}
#endif

LM_API lm_bool_t
LM_EnumSymbols(lm_module_t mod,
	       lm_bool_t (*callback)(lm_cstring_t symbol,
	       			     lm_address_t addr,
	       			     lm_void_t   *arg),
	       lm_void_t *arg)
{
	LM_ASSERT(callback != LM_NULLPTR);

	return _LM_EnumSymbols(mod, callback, arg);
}
/********************************/
#if LM_OS == LM_OS_WIN
LM_API lm_bool_t
_LM_EnumSymbolsEx(lm_process_t proc,
		  lm_module_t  mod,
	          lm_bool_t  (*callback)(lm_cstring_t symbol,
		 			 lm_address_t addr,
					 lm_void_t   *arg),
		  lm_void_t *arg)
{
	lm_bool_t    ret = LM_FALSE;
	lm_address_t alloc;

	alloc = LM_AllocMemory(LM_PROT_RW, mod.size);
	if (alloc == LM_ADDRESS_BAD)
		return ret;
		
	if (LM_ReadMemoryEx(proc, mod.base, (lm_byte_t *)alloc, mod.size)) {
		ret = _LM_EnumPeSyms(LM_GetProcessBitsEx(proc), alloc,
					callback, arg);
	}

	LM_FreeMemory(alloc, mod.size);

	return ret;
}
#else
LM_API lm_bool_t
_LM_EnumSymbolsEx(lm_process_t proc,
		  lm_module_t  mod,
	          lm_bool_t  (*callback)(lm_cstring_t symbol,
		 			 lm_address_t addr,
					 lm_void_t   *arg),
		  lm_void_t *arg)
{
	lm_tchar_t path[LM_PATH_MAX];

	if (!LM_GetModulePathEx(proc, mod, path, LM_PATH_MAX))
		return LM_FALSE;

	return _LM_EnumElfSyms(mod, path, callback, arg);
}
#endif
LM_API lm_bool_t
LM_EnumSymbolsEx(lm_process_t proc,
		 lm_module_t  mod,
	         lm_bool_t  (*callback)(lm_cstring_t symbol,
		 			lm_address_t addr,
					lm_void_t   *arg),
		 lm_void_t *arg)
{
	LM_ASSERT(LM_VALID_PROCESS(proc) && callback != LM_NULLPTR);

	return _LM_EnumSymbolsEx(proc, mod, callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_address_t
_LM_GetSymbol(lm_module_t  mod,
	      lm_cstring_t symstr)
{
	lm_address_t symaddr = LM_ADDRESS_BAD;
	HMODULE      hModule;
	PVOID        procaddr;

	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
			  (LPTSTR)mod.base, &hModule);		
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
_LM_GetSymbol(lm_module_t  mod,
	      lm_cstring_t symstr)
{
	lm_address_t symaddr = LM_ADDRESS_BAD;
	lm_process_t proc;

	if (!LM_OpenProcess(&proc))
		return symaddr;

	symaddr = LM_GetSymbolEx(proc, mod, symstr);

	LM_CloseProcess(&proc);

	return symaddr;
}
#endif

LM_API lm_address_t
LM_GetSymbol(lm_module_t  mod,
	     lm_cstring_t symstr)
{
	LM_ASSERT(symstr != LM_NULLPTR);

	return _LM_GetSymbol(mod, symstr);
}

/********************************/

typedef struct {
	lm_cstring_t symbol;
	lm_address_t addr;
} _lm_get_symbol_t;

LM_PRIVATE lm_bool_t
_LM_GetSymbolExCallback(lm_cstring_t symbol,
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
LM_GetSymbolEx(lm_process_t proc,
	       lm_module_t  mod,
	       lm_cstring_t symstr)
{
	_lm_get_symbol_t arg;

	LM_ASSERT(LM_VALID_PROCESS(proc) && symstr != LM_NULLPTR);

	arg.symbol = symstr;
	arg.addr   = LM_ADDRESS_BAD;

	LM_EnumSymbolsEx(proc, mod, _LM_GetSymbolExCallback, (lm_void_t *)&arg);

	return arg.addr;
}

/********************************/

/********************************/

/********************************/




