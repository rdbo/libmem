#include "internal.h"

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumPages(lm_bool_t(*callback)(lm_page_t  page,
				   lm_void_t *arg),
	      lm_void_t *arg)
{
	lm_address_t addr;
	MEMORY_BASIC_INFORMATION mbi;
	lm_page_t page;

	/* TODO: Only loop through real pages */
	for (addr = (lm_address_t)0;
	     VirtualQuery(addr, &mbi, sizeof(mbi));
	     addr = (lm_address_t)(
		     &((lm_byte_t *)mbi.BaseAddress)[mbi.RegionSize]
	     )) {
		page.base  = (lm_address_t)mbi.BaseAddress;
		page.size  = (lm_size_t)mbi.RegionSize;
		page.end   = (lm_address_t)(
			&((lm_byte_t *)page.base)[page.size]
		);
		page.prot  = mbi.Protect;
		page.flags = mbi.Type;

		if (callback(page, arg) == LM_FALSE)
			break;
	}

	return LM_TRUE;
}
#else
LM_PRIVATE lm_bool_t
_LM_EnumPages(lm_bool_t(*callback)(lm_page_t  page,
				   lm_void_t *arg),
	      lm_void_t *arg)
{
	lm_bool_t ret = LM_FALSE;
	lm_process_t proc;

	if (LM_OpenProcess(&proc)) {
		ret = LM_EnumPagesEx(proc, callback, arg);
		LM_CloseProcess(&proc);
	}

	return ret;
}
#endif

LM_API lm_bool_t
LM_EnumPages(lm_bool_t(*callback)(lm_page_t  page,
				  lm_void_t *arg),
	     lm_void_t *arg)
{
	LM_ASSERT(callback != LM_NULLPTR);

	return _LM_EnumPages(callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumPagesEx(lm_process_t proc,
		lm_bool_t  (*callback)(lm_page_t  page,
				       lm_void_t *arg),
		lm_void_t   *arg)
{
	lm_address_t addr;
	MEMORY_BASIC_INFORMATION mbi;

	for (addr = (lm_address_t)0;
	     VirtualQueryEx(proc.handle, addr, &mbi, sizeof(mbi));
	     addr = (lm_address_t)(
		     &((lm_byte_t *)mbi.BaseAddress)[mbi.RegionSize]
	     )) {
		lm_page_t page;

		page.base  = (lm_address_t)mbi.BaseAddress;
		page.size  = (lm_size_t)mbi.RegionSize;
		page.end   = (lm_address_t)(
			&((lm_byte_t *)page.base)[page.size]
		);
		page.prot  = mbi.Protect;
		page.flags = mbi.Type;

		if (callback(page, arg) == LM_FALSE)
			break;
	}

	return LM_TRUE;
}
#else
LM_PRIVATE lm_bool_t
_LM_EnumPagesEx(lm_process_t proc,
		lm_bool_t  (*callback)(lm_page_t  page,
				       lm_void_t *arg),
		lm_void_t   *arg)
{
	lm_bool_t  ret = LM_FALSE;
	lm_tchar_t *maps_buf;
	lm_tchar_t *ptr;
	lm_tchar_t maps_path[LM_ARRLEN(LM_PROCFS) + 64] = { 0 };

#		if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/maps"), LM_PROCFS, proc.pid);
#		elif LM_OS == LM_OS_BSD
	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/map"), LM_PROCFS, proc.pid);
#		endif
	
	if (!_LM_OpenFileBuf(maps_path, &maps_buf))
		return ret;

	ret = LM_TRUE;

	for (ptr = maps_buf; ptr; ptr = LM_STRCHR(ptr, LM_STR('\n'))) {
		lm_page_t page;

		if (ptr != maps_buf)
			ptr = &ptr[1];
		
		page.base = (lm_address_t)LM_STRTOP(ptr, NULL, 16);

#			if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
		ptr = LM_STRCHR(ptr, LM_STR('-'));
#			elif LM_OS == LM_OS_BSD
		ptr = LM_STRSTR(ptr, LM_STR(" 0x"));
#			endif

		if (!ptr)
			break; /* EOF */

		ptr = &ptr[1];

		page.end = (lm_address_t)LM_STRTOP(ptr, NULL, 16);
		page.size = (lm_size_t)(
			(lm_uintptr_t)page.end - 
			(lm_uintptr_t)page.base
		);

		page.prot  = 0;
		page.flags = 0;

#			if LM_OS == LM_OS_LINUX || LM_OS == LM_OS_ANDROID
		{
			lm_size_t i;

			ptr = LM_STRCHR(ptr, LM_STR(' '));
			ptr = &ptr[1];

			for (i = 0; i < 4; ++i) {
				switch (ptr[i]) {
				case LM_STR('r'):
					page.prot |= PROT_READ;
					break;
				case LM_STR('w'):
					page.prot |= PROT_WRITE;
					break;
				case LM_STR('x'):
					page.prot |= PROT_EXEC;
					break;
				case LM_STR('p'):
					page.flags = MAP_PRIVATE;
					break;
				case LM_STR('s'):
					page.flags = MAP_SHARED;
					break;
				}
			}
		}
#			elif LM_OS == LM_OS_BSD
		{
			lm_size_t i;

			for (i = 0; i < 4; ++i) {
				ptr = LM_STRCHR(ptr, LM_STR(' '));
				ptr = &ptr[1];
			}

			for (i = 0; i < 3; ++i) {
				switch (ptr[i]) {
				case LM_STR('r'):
					page.prot |= PROT_READ;
					break;
				case LM_STR('w'):
					page.prot |= PROT_WRITE;
					break;
				case LM_STR('x'):
					page.prot |= PROT_EXEC;
					break;
				}
			}
		}
#			endif

		if (callback(page, arg) == LM_FALSE)
			break;
	}

	_LM_CloseFileBuf(&maps_buf);

	return ret;
}
#endif

LM_API lm_bool_t
LM_EnumPagesEx(lm_process_t proc,
	       lm_bool_t  (*callback)(lm_page_t  page,
				      lm_void_t *arg),
	       lm_void_t   *arg)
{
	LM_ASSERT(LM_VALID_PROCESS(proc) && callback != LM_NULLPTR);

	return _LM_EnumPagesEx(proc, callback, arg);
}

/********************************/

typedef struct {
	lm_address_t addr;
	lm_page_t   *pagebuf;
} _lm_get_page_t;

LM_PRIVATE lm_bool_t
_LM_GetPageCallback(lm_page_t  page,
		    lm_void_t *arg)
{
	_lm_get_page_t *parg = (_lm_get_page_t *)arg;
	
	if ((lm_uintptr_t)parg->addr >= (lm_uintptr_t)page.base &&
	    (lm_uintptr_t)parg->addr < (lm_uintptr_t)page.end) {
		*parg->pagebuf = page;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_bool_t
LM_GetPage(lm_address_t addr,
	   lm_page_t   *page)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_page_t arg;

	LM_ASSERT(addr != LM_ADDRESS_BAD && page != LM_NULLPTR);

	arg.addr = addr;
	arg.pagebuf = page;
	arg.pagebuf->base = (lm_address_t)LM_BAD;
	arg.pagebuf->size = 0;
	arg.pagebuf->end  = (lm_address_t)LM_BAD;

	LM_EnumPages(_LM_GetPageCallback, (lm_void_t *)&arg);

	ret = page->size > 0 ? LM_TRUE : LM_FALSE;

	return ret;
}

/********************************/

LM_API lm_bool_t
LM_GetPageEx(lm_process_t proc,
	     lm_address_t addr,
	     lm_page_t   *page)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_page_t arg;

	LM_ASSERT(LM_VALID_PROCESS(proc) &&
		  addr != LM_ADDRESS_BAD &&
		  page != LM_NULLPTR);

	arg.addr = addr;
	arg.pagebuf = page;
	arg.pagebuf->base = (lm_address_t)LM_BAD;
	arg.pagebuf->size = 0;
	arg.pagebuf->end  = (lm_address_t)LM_BAD;

	LM_EnumPagesEx(proc, _LM_GetPageCallback, (lm_void_t *)&arg);

	ret = page->size > 0 ? LM_TRUE : LM_FALSE;
	return ret;
}

