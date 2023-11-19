#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

struct enum_pages_cbarg {
	lm_module_t mod;
	lm_bool_t check;
};

lm_bool_t _LM_EnumPagesCallback(lm_page_t *ppage, lm_void_t *arg)
{
	struct enum_pages_cbarg *parg = (struct enum_pages_cbarg *)arg;

	/* Check if process module has at least one executable page */
	if (ppage->base >= parg->mod.base && ppage->base <= parg->mod.end && (ppage->prot | LM_PROT_X)) {
		parg->check = LM_TRUE;
		return LM_FALSE;
	}

	return LM_TRUE;
}

char *test_LM_EnumPages(lm_process_t *pcurproc)
{
	struct enum_pages_cbarg arg;
	arg.check = LM_FALSE;

	/* TODO: Get module from 'module' test */
	mu_assert("failed to retrieve current process module", LM_FindModule(pcurproc->name, &arg.mod) == LM_TRUE);
	mu_assert("failed to enumerate pages", LM_EnumPages(_LM_EnumPagesCallback, &arg) == LM_TRUE);
	mu_assert("could not find executable page in process module", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumPages(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_EnumPagesEx(lm_process_t *ptargetproc)
{
	struct enum_pages_cbarg arg;
	arg.check = LM_FALSE;

	/* TODO: Get module from 'module' test */
	mu_assert("failed to retrieve current process module", LM_FindModuleEx(ptargetproc, ptargetproc->name, &arg.mod) == LM_TRUE);
	mu_assert("failed to enumerate pages", LM_EnumPagesEx(ptargetproc, _LM_EnumPagesCallback, &arg) == LM_TRUE);
	mu_assert("could not find executable page in process module", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid process)", LM_EnumPagesEx(LM_NULLPTR, _LM_EnumPagesCallback, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumPagesEx(ptargetproc, LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetPage(lm_process_t *pcurproc)
{
	lm_module_t mod;
	lm_page_t page;
	/* TODO: Get module from 'module' test */
	mu_assert("failed to retrieve current process module", LM_FindModule(pcurproc->name, &mod) == LM_TRUE);
	mu_assert("failed to get page", LM_GetPage(mod.base, &page) == LM_TRUE);
	mu_assert("page is invalid", CHECK_PAGE(&page));
	mu_assert("function attempted to run with bad arguments (invalid pagebuf)", LM_GetPage(mod.base, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_GetPageEx(lm_process_t *ptargetproc)
{
	lm_module_t mod;
	lm_page_t page;
	/* TODO: Get module from 'module' test */
	mu_assert("failed to retrieve current process module", LM_FindModuleEx(ptargetproc, ptargetproc->name, &mod) == LM_TRUE);
	mu_assert("failed to get page", LM_GetPageEx(ptargetproc, mod.base, &page) == LM_TRUE);
	mu_assert("page is invalid", CHECK_PAGE(&page));
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_GetPageEx(LM_NULLPTR, mod.base, &page) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid pagebuf)", LM_GetPageEx(ptargetproc, mod.base, LM_NULLPTR) == LM_FALSE);

	return NULL;
}