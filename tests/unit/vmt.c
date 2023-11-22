#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

typedef struct {
	void **vtable;
	char *name;
	int number;
} CppObject;

int CppObject_print(CppObject *thisptr)
{
	printf(" <CppObject: %s %d> ", thisptr->name, thisptr->number);
	return thisptr->number;
}

int hk_CppObject_print(void *obj)
{
	printf(" <Hooked CppObject_print!> ");
	return 1337;
}

static const void *CppObject_vtable[] = {
	(void *)CppObject_print
};

void initCppObject(CppObject *obj)
{
	obj->vtable = (void **)CppObject_vtable;
	obj->name = "MyObject";
	obj->number = 20;
}

static CppObject cppObject;

char *test_LM_VmtNew(lm_vmt_t *vmt)
{
	initCppObject(&cppObject);
	
	mu_assert("failed to create vmt", LM_VmtNew((lm_address_t *)cppObject.vtable, vmt) == LM_TRUE);
	mu_assert("vmt is invalid", vmt->vtable == (lm_address_t *)cppObject.vtable && !vmt->hkentries);
	mu_assert("function attempted to run with bad arguments (invalid vtable)", LM_VmtNew(LM_NULLPTR, vmt) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid vtable)", LM_VmtNew((lm_address_t *)cppObject.vtable, LM_NULLPTR) == LM_FALSE);

	return NULL;
}

char *test_LM_VmtHook(lm_vmt_t *vmt)
{
	int result;
	
	mu_assert("failed to hook vmt function", LM_VmtHook(vmt, 0, (lm_address_t)hk_CppObject_print) == LM_TRUE);
	mu_assert("vmt hook entries is NULL", vmt->hkentries != LM_NULLPTR);
	mu_assert("vmt hook entries is not set properly", vmt->hkentries->index == 0 && vmt->hkentries->orig_func == (lm_address_t)CppObject_print);

	result = ((int (*)(CppObject *))cppObject.vtable[0])(&cppObject);
	mu_assert("hooked function call does not return the expected value", result == 1337);
	
	mu_assert("function attempted to run with bad parameters (invalid vmt)", LM_VmtHook(LM_NULLPTR, 0, (lm_address_t)hk_CppObject_print) == LM_FALSE);

	return NULL;
}

char *test_LM_VmtGetOriginal(lm_vmt_t *vmt)
{
	lm_address_t orig;
	int result;

	orig = LM_VmtGetOriginal(vmt, 0);
	mu_assert("original function from vmt does not match real address", orig == (lm_address_t)CppObject_print);
	result = ((int (*)(CppObject *))orig)(&cppObject);
	mu_assert("return value from original function is invalid", result == cppObject.number);
	mu_assert("function attempted to run with bad arguments (invalid vmt)", LM_VmtGetOriginal(LM_NULLPTR, 0) == LM_ADDRESS_BAD);

	return NULL;
}

char *test_LM_VmtUnhook(lm_vmt_t *vmt)
{
	int result;
	
	mu_assert("failed to unhook vmt function", LM_VmtUnhook(vmt, 0) == LM_TRUE);
	
	result = ((int (*)(CppObject *))cppObject.vtable[0])(&cppObject);
	mu_assert("return value from vtable function is invalid", result == cppObject.number);

	mu_assert("attempted to unhook invalid index", LM_VmtUnhook(vmt, 100) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid vmt)", LM_VmtUnhook(LM_NULLPTR, 0) == LM_FALSE);

	return NULL;
}

char *test_LM_VmtReset(lm_vmt_t *vmt)
{
	int result;

	mu_assert("failed to rehook vmt function", LM_VmtHook(vmt, 0, (lm_address_t)hk_CppObject_print));
	LM_VmtReset(vmt);
	
	result = ((int (*)(CppObject *))cppObject.vtable[0])(&cppObject);
	mu_assert("return value from vtable function is invalid", result == cppObject.number);

	return NULL;
}

char *test_LM_VmtFree(lm_vmt_t *vmt)
{
	int result;

	mu_assert("failed to rehook vmt function", LM_VmtHook(vmt, 0, (lm_address_t)hk_CppObject_print));
	LM_VmtFree(vmt);
	
	result = ((int (*)(CppObject *))cppObject.vtable[0])(&cppObject);
	mu_assert("return value from vtable function is invalid", result == cppObject.number);

	return NULL;
}