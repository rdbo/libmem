#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

#if LM_OS == LM_OS_WIN
#	define LIB_PATH "libtest.dll"
#else
#	define LIB_PATH "libtest.so"
#endif

struct enum_modules_cbarg {
	lm_process_t *pproc;
	lm_bool_t check;
};

lm_bool_t _LM_EnumModulesCallback(lm_module_t *pmod, lm_void_t *arg)
{
	struct enum_modules_cbarg *cbarg = (struct enum_modules_cbarg *)arg;

	if (CHECK_MODULE(pmod) && !LM_STRCMP(pmod->name, cbarg->pproc->name)) {
		cbarg->check = LM_TRUE;
		return LM_FALSE;
	}

	return LM_TRUE;
}

char *test_LM_EnumModules()
{
	struct enum_modules_cbarg arg;
	arg.pproc = &current_process;
	arg.check = LM_FALSE;

	mu_assert("failed to enumerate modules", LM_EnumModules(_LM_EnumModulesCallback, (lm_void_t *)&arg) == LM_TRUE);
	mu_assert("process module not found in callback", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments", LM_EnumModules(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

char *test_LM_EnumModulesEx()
{
	struct enum_modules_cbarg arg;
	arg.pproc = &target_process;
	arg.check = LM_FALSE;

	mu_assert("failed to enumerate modules", LM_EnumModulesEx(&target_process, _LM_EnumModulesCallback, (lm_void_t *)&arg) == LM_TRUE);
	mu_assert("process module not found in callback", arg.check == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_EnumModulesEx(LM_NULLPTR, _LM_EnumModulesCallback, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumModulesEx(&target_process, LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_FindModule()
{
	lm_module_t mod;
	
	mu_assert("failed to find current process module", LM_FindModule(current_process.name, &mod) == LM_TRUE);
	mu_assert("found module is invalid", CHECK_MODULE(&mod));
	mu_assert("function attempted to run with bad arguments (invalid name)", LM_FindModule(LM_NULLPTR, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid modbuf)", LM_FindModule(current_process.name, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

char *test_LM_FindModuleEx()
{
	lm_module_t mod;
	
	mu_assert("failed to find process module", LM_FindModuleEx(&target_process, target_process.name, &mod) == LM_TRUE);
	mu_assert("found module is invalid", CHECK_MODULE(&mod));
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_FindModuleEx(LM_NULLPTR, current_process.name, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid name)", LM_FindModuleEx(&target_process, LM_NULLPTR, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid modbuf)", LM_FindModuleEx(&target_process, current_process.name, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

lm_module_t libtest_mod;

char *test_LM_LoadModule()
{
	mu_assert("failed to load module into current process", LM_LoadModule(LIB_PATH, &libtest_mod) == LM_TRUE);
	mu_assert("loaded module is invalid", CHECK_MODULE(&libtest_mod));
	mu_assert("function attempted to run with bad arguments", LM_LoadModule(LM_NULLPTR, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_UnloadModule()
{
	lm_module_t mod;

	mu_assert("failed to unload module from current process", LM_UnloadModule(&libtest_mod) == LM_TRUE);
	mu_assert("module has not been properly unloaded", LM_FindModule(libtest_mod.name, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments", LM_UnloadModule(LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_LoadModuleEx()
{
	lm_module_t mod;

	mu_assert("failed to load module into target process", LM_LoadModuleEx(&target_process, LIB_PATH, &mod) == LM_TRUE);
	mu_assert("loaded module is invalid", CHECK_MODULE(&mod));
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_LoadModuleEx(LM_NULLPTR, LIB_PATH, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid path)", LM_LoadModuleEx(&target_process, LM_NULLPTR, &mod) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid path)", LM_LoadModuleEx(&target_process, LIB_PATH, LM_NULLPTR) == LM_FALSE);

	return NULL;
}