#include "internal.h"

typedef struct {
	lm_bool_t (LM_CALL *callback)(lm_page_t *ppage, lm_void_t *arg);
	lm_void_t          *arg;
} _lm_enum_pages_t;

LM_PRIVATE lm_bool_t LM_CALL
_LM_EnumPagesCallback(lm_module_t *pmod,
		      lm_void_t   *arg)
{
	lm_address_t addr;
	_lm_enum_pages_t *parg = (_lm_enum_pages_t *)arg;
	MEMORY_BASIC_INFORMATION mbi;
	lm_page_t page;

	for (addr = pmod->base;
	     VirtualQuery(addr, &mbi, sizeof(mbi));
	     addr = (lm_address_t)LM_OFFSET(mbi.BaseAddress, mbi.RegionSize)) {
		page.base  = (lm_address_t)mbi.BaseAddress;
		page.size  = (lm_size_t)mbi.RegionSize;
		page.end   = (lm_address_t)LM_OFFSET(page.base, page.size);
		page.prot  = _LM_GetProt((lm_prot_t)mbi.Protect);

		if (parg->callback(&page, parg->arg) == LM_FALSE)
			return LM_FALSE;
	}

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumPages(lm_bool_t (LM_CALL *callback)(lm_page_t *ppage,
					    lm_void_t *arg),
	      lm_void_t          *arg)
{
	_lm_enum_pages_t data;

	data.callback = callback;
	data.arg = arg;

	return LM_EnumModules(_LM_EnumPagesCallback, (lm_void_t *)&data);
}

/********************************/

typedef struct {
	const lm_process_t *pproc;
	lm_bool_t (LM_CALL *callback)(lm_page_t *ppage, lm_void_t *arg);
	lm_void_t *arg;
	HANDLE hProcess;
} _lm_enum_pages_ex_t;

LM_PRIVATE lm_bool_t LM_CALL
_LM_EnumPagesExCallback(lm_module_t *pmod,
			lm_void_t   *arg)
{
	lm_address_t addr;
	_lm_enum_pages_ex_t *parg = (_lm_enum_pages_ex_t *)arg;
	MEMORY_BASIC_INFORMATION mbi;
	lm_page_t page;

	for (addr = pmod->base;
	     VirtualQueryEx(parg->hProcess, addr, &mbi, sizeof(mbi));
	     addr = (lm_address_t)LM_OFFSET(mbi.BaseAddress, mbi.RegionSize)) {
		page.base  = (lm_address_t)mbi.BaseAddress;
		page.size  = (lm_size_t)mbi.RegionSize;
		page.end   = (lm_address_t)LM_OFFSET(page.base, page.size);
		page.prot  = _LM_GetProt((lm_prot_t)mbi.Protect);

		if (parg->callback(&page, parg->arg) == LM_FALSE)
			return LM_FALSE;
	}

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_EnumPagesEx(const lm_process_t *pproc,
		lm_bool_t (LM_CALL *callback)(lm_page_t *ppage,
					      lm_void_t *arg),
		lm_void_t          *arg)
{
	lm_bool_t ret = LM_FALSE;
	_lm_enum_pages_ex_t data;

	if (!_LM_OpenProc(pproc->pid, &data.hProcess))
		return ret;

	data.pproc = pproc;
	data.callback = callback;
	data.arg = arg;

	ret = LM_EnumModulesEx(pproc, _LM_EnumPagesExCallback, (lm_void_t *)&data);

	_LM_CloseProc(&data.hProcess);

	return ret;
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_GetPage(lm_address_t addr,
	    lm_page_t   *pagebuf)
{
	MEMORY_BASIC_INFORMATION mbi;

	if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
		return LM_FALSE;

	pagebuf->base  = (lm_address_t)mbi.BaseAddress;
	pagebuf->size  = (lm_size_t)mbi.RegionSize;
	pagebuf->end   = (lm_address_t)LM_OFFSET(pagebuf->base, pagebuf->size);
	pagebuf->prot  = _LM_GetProt((lm_prot_t)mbi.Protect);

	return LM_TRUE;
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_GetPageEx(const lm_process_t *pproc,
	      lm_address_t        addr,
	      lm_page_t          *pagebuf)
{
	MEMORY_BASIC_INFORMATION mbi;
	HANDLE hProcess;
	SIZE_T query_ret;

	if (!_LM_OpenProc(pproc->pid, &hProcess))
		return LM_FALSE;

	query_ret = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

	_LM_CloseProc(&hProcess);

	if (!query_ret)
		return LM_FALSE;

	pagebuf->base  = (lm_address_t)mbi.BaseAddress;
	pagebuf->size  = (lm_size_t)mbi.RegionSize;
	pagebuf->end   = (lm_address_t)LM_OFFSET(pagebuf->base, pagebuf->size);
	pagebuf->prot  = _LM_GetProt((lm_prot_t)mbi.Protect);

	return LM_TRUE;	
}
