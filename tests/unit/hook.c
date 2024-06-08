#include <libmem/libmem.h>
#include <stdint.h>
#include "minunit.h"
#include "helpers.h"

#ifdef _WIN32
#	include <windows.h>
#	define sleep Sleep
#else
#	include <unistd.h>
#endif

static int (*target_function_trampoline)(char *, int);
static lm_address_t hook_address;
static lm_address_t wait_message_addr;

int target_function(char *mystr, int mynum)
{
	if (!mystr || mynum < 0)
		return 0;

	printf("<STRING: %s> <NUMBER: %d> ", mystr, mynum);
	fflush(stdout);

	return 1;
}

int hk_target_function(char *mystr, int mynum)
{
	int orig_ret;

	mystr = "Hooked Target Function";
	mynum = 1337;

	orig_ret = target_function_trampoline(mystr, mynum);
	printf("<ORIG RET: %d> ", orig_ret);
	fflush(stdout);

	return mynum;
}

char *test_LM_HookCode(struct hook_args *arg)
{
	lm_inst_t inst;

	hook_address = (lm_address_t)target_function;
	/*
	 * NOTE: this resolves dummy functions for Windows.
	 * On Windows (x86), the function 'target_function' is
	 * just a gateway, having the instruction `jmp <real_target_function>`.
	 * This invalidates the gateway, which will just jump to the real function.
	 * The following code will resolve that.
	 */
	LM_Disassemble((lm_address_t)target_function, &inst);
	if (!strcmp(inst.mnemonic, "jmp")) {
		hook_address += *(uint32_t *)&inst.bytes[1] + (uint32_t)inst.size; /* Calculate real address from 'jmp' offset */
		printf("<RESOLVED JMP TO: %p> ", (void *)hook_address);
		fflush(stdout);
	}
	
	arg->hksize = LM_HookCode(hook_address, (lm_address_t)hk_target_function, &arg->trampoline);
	mu_assert("failed to hook target function", arg->hksize > 0);
	target_function_trampoline = (int (*)(char *, int))arg->trampoline;
	LM_Disassemble((lm_address_t)target_function, &inst);
	printf("<FROM DISASM: %s %s> ", inst.mnemonic, inst.op_str);
	fflush(stdout);
	mu_assert("target function not hooked", target_function(NULL, -1) == 1337);
	mu_assert("function attempted to run with bad arguments (invalid from)", LM_HookCode(LM_ADDRESS_BAD, (lm_address_t)hk_target_function, LM_NULLPTR) == 0);
	mu_assert("function attempted to run with bad arguments (invalid to)", LM_HookCode(hook_address, LM_ADDRESS_BAD, LM_NULLPTR) == 0);
	
	return NULL;
}

char *test_LM_UnhookCode(struct hook_args *arg)
{
	mu_assert("failed to unhook target function", LM_UnhookCode(hook_address, arg->trampoline, arg->hksize) == LM_TRUE);
	mu_assert("target function is not unhooked properly", target_function("hello world", 123) == 1);
	mu_assert("function attempted to run with bad arguments (invalid from)", LM_UnhookCode(LM_ADDRESS_BAD, arg->trampoline, arg->hksize) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid trampoline)", LM_UnhookCode((lm_address_t)target_function, LM_ADDRESS_BAD, arg->hksize) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_UnhookCode((lm_address_t)target_function, arg->trampoline, 0) == LM_FALSE);

	return NULL;
}

char *test_LM_HookCodeEx(struct hook_args *arg)
{
	lm_address_t hk_wait_message_addr;
	lm_inst_t inst;

	wait_message_addr = LM_FindSymbolAddress(arg->ptargetmod, "wait_message");
	mu_assert("failed to find wait_message function on target module", wait_message_addr != LM_ADDRESS_BAD);

	/* Same fix as `test_LM_HookCode` */
#	ifdef _WIN32
	uint32_t offset;

	mu_assert("failed to get real function address", LM_ReadMemoryEx(arg->ptargetproc, wait_message_addr + 1, &offset, sizeof(offset)) != 0);
	wait_message_addr += (lm_address_t)offset + 5;
	printf("<RESOLVED JMP TO: %p> ", (void *)wait_message_addr);
	fflush(stdout);
#	endif

	printf("<wait_message: %p> ", (void *)wait_message_addr);
	fflush(stdout);

	hk_wait_message_addr = LM_FindSymbolAddress(arg->ptargetmod, "hk_wait_message");
	mu_assert("failed to find hk_wait_message function on target module", hk_wait_message_addr != LM_ADDRESS_BAD);

	printf("<hk_wait_message: %p> ", (void *)hk_wait_message_addr);
	fflush(stdout);

	arg->hksize = LM_HookCodeEx(arg->ptargetproc, wait_message_addr, hk_wait_message_addr, &arg->trampoline);
	mu_assert("failed to hook target function", arg->hksize > 0);

	printf("<trampoline: %p> ", (void *)arg->trampoline);

	LM_ReadMemoryEx(arg->ptargetproc, wait_message_addr, inst.bytes, sizeof(inst.bytes));
	LM_Disassemble((lm_address_t)inst.bytes, &inst);
	printf("<FROM DISASM: %s %s> ", inst.mnemonic, inst.op_str);
	fflush(stdout);

	printf("<WAITING FOR FUNCTION TO RUN> ");
	fflush(stdout);
	sleep(3);

	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_HookCodeEx(LM_NULLPTR, wait_message_addr, hk_wait_message_addr, LM_NULLPTR) == 0);
	mu_assert("function attempted to run with bad arguments (invalid from)", LM_HookCodeEx(arg->ptargetproc, LM_ADDRESS_BAD, hk_wait_message_addr, LM_NULLPTR) == 0);
	mu_assert("function attempted to run with bad arguments (invalid to)", LM_HookCodeEx(arg->ptargetproc, wait_message_addr, LM_ADDRESS_BAD, LM_NULLPTR) == 0);

	return NULL;
}

char *test_LM_UnhookCodeEx(struct hook_args *arg)
{
	mu_assert("failed to unhook target function", LM_UnhookCodeEx(arg->ptargetproc, wait_message_addr, arg->trampoline, arg->hksize) == LM_TRUE);
	mu_assert("function attempted to run with bad arguments (invalid proc)", LM_UnhookCodeEx(LM_NULLPTR, wait_message_addr, arg->trampoline, arg->hksize) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid from)", LM_UnhookCodeEx(arg->ptargetproc, LM_ADDRESS_BAD, arg->trampoline, arg->hksize) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid trampoline)", LM_UnhookCodeEx(arg->ptargetproc, wait_message_addr, LM_ADDRESS_BAD, arg->hksize) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid size)", LM_UnhookCodeEx(arg->ptargetproc, wait_message_addr, arg->trampoline, 0) == LM_FALSE);

	return NULL;
}
