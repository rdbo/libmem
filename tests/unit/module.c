#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

struct enum_modules_cbarg {
	lm_process_t *pproc;
	lm_bool_t check;
};

lm_bool_t _LM_EnumModulesCallback(lm_module_t *pmod, lm_void_t *arg)
{
	struct enum_modules_cbarg *cbarg = (struct enum_modules_cbarg *)arg;

	if (CHECK_MODULE(pmod) && !strcmp(pmod->name, cbarg->pproc->name)) {
		cbarg->check = LM_TRUE;
		return LM_FALSE;
	}

	return LM_TRUE;
}

char *test_LM_EnumModules(lm_process_t *pcurproc)
{
	struct enum_modules_cbarg arg;
	arg.pproc = pcurproc;
	arg.check = LM_FALSE;

	mu_assert("failed to enumerate modules", LM_EnumModules(_LM_EnumModulesCallback, (lm_void_t *)&arg) == LM_TRUE);
	mu_assert("process module not found in callback", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments", LM_EnumModules(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

char *test_LM_EnumModulesEx(lm_process_t *ptargetproc)
{
	struct enum_modules_cbarg arg;
	arg.pproc = ptargetproc;
	arg.check = LM_FALSE;

	mu_assert("failed to enumerate modules", LM_EnumModulesEx(ptargetproc, _LM_EnumModulesCallback, (lm_void_t *)&arg) == LM_TRUE);
	mu_assert("process module not found in callback", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_EnumModulesEx(LM_NULLPTR, _LM_EnumModulesCallback, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumModulesEx(ptargetproc, LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_FindModule(lm_process_t *pcurproc)
{
	lm_module_t mod;
	
	mu_assert("failed to find current process module", LM_FindModule(pcurproc->name, &mod) == LM_TRUE);
	mu_assert("found module is invalid", CHECK_MODULE(&mod));
	printf("<MODNAME: %s> <MODBASE: %p> ", mod.name, (void *)mod.base);
	fflush(stdout);
	mu_assert("function attempted to run with bad arguments (invalid name)", LM_FindModule(LM_NULLPTR, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid modbuf)", LM_FindModule(pcurproc->name, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

char *test_LM_FindModuleEx(lm_process_t *ptargetproc)
{
	lm_module_t mod;
	
	mu_assert("failed to find process module", LM_FindModuleEx(ptargetproc, ptargetproc->name, &mod) == LM_TRUE);
	mu_assert("found module is invalid", CHECK_MODULE(&mod));
	printf("<MODNAME: %s> <MODBASE: %p> ", mod.name, (void *)mod.base);
	fflush(stdout);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_FindModuleEx(LM_NULLPTR, ptargetproc->name, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid name)", LM_FindModuleEx(ptargetproc, LM_NULLPTR, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid modbuf)", LM_FindModuleEx(ptargetproc, ptargetproc->name, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

char *test_LM_LoadModule(lm_module_t *pmod)
{
	memset(pmod, 0, sizeof(lm_module_t)); /* Prevent the module from having correct values without running the function */

	mu_assert("failed to load module into current process", LM_LoadModule(LIBTEST_PATH, pmod) == LM_TRUE);
	mu_assert("loaded module is invalid", CHECK_MODULE(pmod));
	printf("<MODNAME: %s> <MODBASE: %p> ", pmod->name, (void *)pmod->base);
	fflush(stdout);
	mu_assert("function attempted to run with bad arguments", LM_LoadModule(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_UnloadModule(lm_module_t *pmod)
{
	mu_assert("failed to unload module from current process", LM_UnloadModule(pmod) == LM_TRUE);
	mu_assert("function attempted to run with bad arguments", LM_UnloadModule(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_LoadModuleEx(struct load_module_args *arg)
{
	lm_process_t *ptargetproc = arg->ptargetproc;
	lm_module_t *pmod = arg->pmod;
	memset(pmod, 0, sizeof(lm_module_t)); /* Prevent the module from having correct values without running the function */

	mu_assert("failed to load module into target process", LM_LoadModuleEx(ptargetproc, LIBTEST_PATH, pmod) == LM_TRUE);
	mu_assert("loaded module is invalid", CHECK_MODULE(pmod));
	printf("<MODNAME: %s> <MODBASE: %p> ", pmod->name, (void *)pmod->base);
	fflush(stdout);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_LoadModuleEx(LM_NULLPTR, LIBTEST_PATH, pmod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid path)", LM_LoadModuleEx(ptargetproc, LM_NULLPTR, pmod) == LM_FALSE);

	return NULL;
}

char *test_LM_UnloadModuleEx(struct load_module_args *arg)
{
	lm_process_t *ptargetproc = arg->ptargetproc;
	lm_module_t *pmod = arg->pmod;

	mu_assert("failed to unload external module", LM_UnloadModuleEx(ptargetproc, pmod) == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_UnloadModuleEx(LM_NULLPTR, pmod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid mod)", LM_UnloadModuleEx(ptargetproc, LM_NULLPTR) == LM_FALSE);
}
