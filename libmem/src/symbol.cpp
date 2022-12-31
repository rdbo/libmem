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
	return _LM_EnumPeSyms(LM_GetProcessBits(), pmod->base, callback, arg);
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
_LM_EnumSymbolsEx(lm_pid_t     pid,
		  lm_module_t *pmod,
	          lm_bool_t  (*callback)(lm_cstring_t symbol,
					 lm_address_t addr,
					 lm_void_t   *arg),
		  lm_void_t   *arg)
{
	/* TODO: Reimplement */
	return LM_FALSE;
}
#else
LM_API lm_bool_t
_LM_EnumSymbolsEx(lm_pid_t     pid,
		  lm_module_t *pmod,
	          lm_bool_t  (*callback)(lm_cstring_t symbol,
					 lm_address_t addr,
					 lm_void_t   *arg),
		  lm_void_t   *arg)
{
	lm_tchar_t path[LM_PATH_MAX];

	if (!LM_GetModulePathEx(pid, pmod, path, LM_PATH_MAX))
		return LM_FALSE;

	return _LM_EnumElfSyms(pmod, path, callback, arg);
}
#endif
LM_API lm_bool_t
LM_EnumSymbolsEx(lm_pid_t     pid,
		 lm_module_t *pmod,
	         lm_bool_t  (*callback)(lm_cstring_t symbol,
					lm_address_t addr,
					lm_void_t   *arg),
		 lm_void_t   *arg)
{
	LM_ASSERT(pid != LM_PID_BAD && callback != LM_NULLPTR);

	return _LM_EnumSymbolsEx(pid, pmod, callback, arg);
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
		return LM_FALSE;

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
LM_FindSymbolEx(lm_pid_t     pid,
		lm_module_t *pmod,
		lm_cstring_t symstr)
{
	_lm_get_symbol_t arg;

	LM_ASSERT(pid != LM_PID_BAD &&
		  pmod != LM_NULLPTR &&
		  symstr != LM_NULLPTR);

	arg.symbol = symstr;
	arg.addr   = LM_ADDRESS_BAD;

	LM_EnumSymbolsEx(pid, pmod,
			 _LM_FindSymbolExCallback, (lm_void_t *)&arg);

	return arg.addr;
}

