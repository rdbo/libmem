#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

static int (*target_function_trampoline)(char *, int);

int target_function(char *mystr, int mynum)
{
	if (!mystr || mynum < 0)
		return 0;

	printf("<STRING: %s> <NUMBER: %d> ", mystr, mynum);

	return 1;
}

int hk_target_function(char *mystr, int mynum)
{
	int orig_ret;

	mystr = "Hooked Target Function";
	mynum = 1337;

	orig_ret = ((int (*)(char *, int))target_function_trampoline)(mystr, mynum);
	printf("<ORIG RET: %d> ", orig_ret);

	return mynum;
}

char *test_LM_HookCode(struct hook_args *arg)
{
	/* TODO: Don't rely on LM_ProtMemory for this test */
	mu_assert("failed to change protection of target function", LM_ProtMemory((lm_address_t)target_function, 1024, LM_PROT_XRW, LM_NULLPTR) == LM_TRUE);
	
	arg->hksize = LM_HookCode((lm_address_t)target_function, (lm_address_t)hk_target_function, &arg->trampoline);
	mu_assert("failed to hook target function", arg->hksize > 0);
	target_function_trampoline = (int (*)(char *, int))arg->trampoline;
	mu_assert("target function not hooked", target_function(NULL, -1) == 1337);
	mu_assert("function attempted to run with bad arguments (invalid from)", LM_HookCode(LM_ADDRESS_BAD, (lm_address_t)hk_target_function, LM_NULLPTR) == 0);
	mu_assert("function attempted to run with bad arguments (invalid to)", LM_HookCode((lm_address_t)target_function, LM_ADDRESS_BAD, LM_NULLPTR) == 0);
	
	return NULL;
}

char *test_LM_UnhookCode(struct hook_args *arg)
{
	mu_assert("failed to unhook target function", LM_UnhookCode((lm_address_t)target_function, arg->trampoline, arg->hksize) == LM_TRUE);
	mu_assert("target function is not unhooked properly", target_function("hello world", 123) == 1);
	mu_assert("function attempted to run with bad arguments (invalid from)", LM_UnhookCode(LM_ADDRESS_BAD, arg->trampoline, arg->hksize) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid trampoline)", LM_UnhookCode((lm_address_t)target_function, LM_ADDRESS_BAD, arg->hksize) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_UnhookCode((lm_address_t)target_function, arg->trampoline, 0) == LM_FALSE);

	return NULL;
}