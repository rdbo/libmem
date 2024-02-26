#include "internal.h"

LM_PRIVATE lm_bool_t
_LM_EnumPages(lm_bool_t (LM_CALL *callback)(lm_page_t *ppage,
					    lm_void_t *arg),
	      lm_void_t          *arg)
{
	lm_process_t proc;

	if (!LM_GetProcess(&proc))
		return LM_FALSE;

	return LM_EnumPagesEx(&proc, callback, arg);
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_EnumPagesEx(const lm_process_t *pproc,
		lm_bool_t (LM_CALL *callback)(lm_page_t *ppage,
					      lm_void_t *arg),
		lm_void_t          *arg)
{
	lm_bool_t   ret = LM_FALSE;
	lm_char_t  *maps_line = NULL;
	size_t      maps_line_len;
	lm_char_t   maps_path[LM_PATH_MAX] = { 0 };
	FILE       *maps_file;
	regex_t     regex;
	regmatch_t  matches[4];
	lm_page_t   page;
	size_t      i;

#	if LM_OS == LM_OS_BSD
	if (regcomp(&regex, "^0x([a-z0-9]+)[[:blank:]]+0x([a-z0-9]+).*0x[a-z0-9]+[[:blank:]]+([a-z-]+)[[:blank:]]+.*$", REG_EXTENDED))
		return ret;

	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/map"), LM_PROCFS, pproc->pid);
#	else
	if (regcomp(&regex, "^([a-z0-9]+)-([a-z0-9]+)[[:blank:]]+(.+).*$", REG_EXTENDED))
		return ret;

	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/maps"), LM_PROCFS, pproc->pid);
#	endif

	maps_file = LM_FOPEN(maps_path, "r");
	if (!maps_file)
		goto FREE_EXIT;

	while (LM_GETLINE(&maps_line, &maps_line_len, maps_file) > 0) {
		if (regexec(&regex, maps_line, LM_ARRLEN(matches), matches, 0))
			continue;

		page.base = (lm_address_t)LM_STRTOP(
			&maps_line[matches[1].rm_so], NULL, 16
		);
		page.end = (lm_address_t)LM_STRTOP(
			&maps_line[matches[2].rm_so], NULL, 16
		);

		page.prot = 0;
		for (i = 0; i < (size_t)(matches[3].rm_eo - matches[3].rm_so); ++i) {
			switch (maps_line[matches[3].rm_so + i]) {
			case 'r': page.prot |= PROT_READ; break;
			case 'w': page.prot |= PROT_WRITE; break;
			case 'x': page.prot |= PROT_EXEC; break;
			}
		}
		page.size = (lm_size_t)(
			(lm_uintptr_t)page.end - (lm_uintptr_t)page.base
		);

		page.prot = _LM_GetProt(page.prot);

		if (callback(&page, arg) == LM_FALSE)
			break;
	}

	ret = LM_TRUE;

	LM_FCLOSE(maps_file);
FREE_EXIT:
	regfree(&regex);

	return ret;
}

/********************************/

typedef struct {
	lm_address_t addr;
	lm_page_t   *pagebuf;
} _lm_get_page_t;

LM_PRIVATE lm_bool_t LM_CALL
_LM_GetPageCallback(lm_page_t *ppage,
		    lm_void_t *arg)
{
	_lm_get_page_t *parg = (_lm_get_page_t *)arg;
	
	if ((lm_uintptr_t)parg->addr >= (lm_uintptr_t)ppage->base &&
	    (lm_uintptr_t)parg->addr < (lm_uintptr_t)ppage->end) {
		*(parg->pagebuf) = *ppage;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_PRIVATE lm_bool_t
_LM_GetPage(lm_address_t addr,
	    lm_page_t   *pagebuf)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_page_t arg;

	arg.addr = addr;
	arg.pagebuf = pagebuf;
	arg.pagebuf->base = LM_ADDRESS_BAD;
	arg.pagebuf->size = 0;
	arg.pagebuf->end  = LM_ADDRESS_BAD;

	LM_EnumPages(_LM_GetPageCallback, (lm_void_t *)&arg);

	ret = arg.pagebuf->size > 0 ? LM_TRUE : LM_FALSE;

	return ret;
}

/********************************/

LM_PRIVATE lm_bool_t
_LM_GetPageEx(const lm_process_t *pproc,
	      lm_address_t        addr,
	      lm_page_t          *pagebuf)
{
	lm_bool_t ret = LM_FALSE;
	_lm_get_page_t arg;
	
	arg.addr = addr;
	arg.pagebuf = pagebuf;
	arg.pagebuf->base = LM_ADDRESS_BAD;
	arg.pagebuf->size = 0;
	arg.pagebuf->end  = LM_ADDRESS_BAD;

	LM_EnumPagesEx(pproc, _LM_GetPageCallback, (lm_void_t *)&arg);

	ret = arg.pagebuf->size > 0 ? LM_TRUE : LM_FALSE;
	return ret;
}
