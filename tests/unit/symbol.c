#include <libmem/libmem.h>
#include "minunit.h"
#include "helpers.h"

extern int main();

static const lm_address_t real_symbol_addr = (lm_address_t)main;
static const lm_string_t real_symbol = "main";
static lm_char_t *alloc_symbol;

lm_bool_t _LM_EnumSymbolsCallback(lm_symbol_t *psymbol, lm_void_t *arg)
{
	if (!strcmp(psymbol->name, real_symbol)) {
		*(lm_address_t *)arg = psymbol->address;
		return LM_FALSE;
	}

	return LM_TRUE;
}

char *test_LM_EnumSymbols(lm_module_t *pmod)
{
	lm_address_t symaddr = LM_ADDRESS_BAD;
	
	mu_assert("failed to enumerate symbols", LM_EnumSymbols(pmod, _LM_EnumSymbolsCallback, (lm_void_t *)&symaddr) == LM_TRUE);
	mu_assert("incorrect symbol address", symaddr == real_symbol_addr);
	mu_assert("function attempted to run with bad arguments (invalid pmod)", LM_EnumSymbols(LM_NULLPTR, _LM_EnumSymbolsCallback, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumSymbols(pmod, LM_NULLPTR, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

char *test_LM_FindSymbolAddress(lm_module_t *pmod)
{
	lm_address_t symaddr = LM_ADDRESS_BAD;

	symaddr = LM_FindSymbolAddress(pmod, real_symbol);

	mu_assert("invalid symbol address", symaddr != LM_ADDRESS_BAD);
	mu_assert("incorrect symbol address", symaddr == real_symbol_addr);
	mu_assert("function attempted to run with bad arguments (invalid pmod)", LM_FindSymbolAddress(LM_NULLPTR, real_symbol) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_FindSymbolAddress(pmod, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

char *test_LM_DemangleSymbol(lm_void_t *_arg)
{
	const lm_string_t mangled = "_ZN4llvm11ms_demangle14ArenaAllocator5allocINS0_29LiteralOperatorIdentifierNodeEJEEEPT_DpOT0_";
	const lm_string_t demangled = "llvm::ms_demangle::LiteralOperatorIdentifierNode* llvm::ms_demangle::ArenaAllocator::alloc<llvm::ms_demangle::LiteralOperatorIdentifierNode>()";

	alloc_symbol = LM_DemangleSymbol(mangled, LM_NULLPTR, 0);
	mu_assert("failed to demangle symbol", alloc_symbol != LM_NULLPTR);

	printf(" <SYMBOL: '%s'> ", alloc_symbol);
	fflush(stdout);

	mu_assert("demangled symbol does not match expected value", !strcmp(demangled, alloc_symbol));
	mu_assert("function attempted to run with bad arguments (invalid symbol)", LM_DemangleSymbol(LM_NULLPTR, LM_NULLPTR, 0) == LM_FALSE);

	/* TODO: test pre-allocated buffer */

	return NULL;
}

char *test_LM_FreeDemangledSymbol(lm_void_t *_arg)
{
	LM_FreeDemangledSymbol(alloc_symbol);

	return NULL;
}

char *test_LM_EnumSymbolsDemangled(lm_module_t *pmod)
{
	lm_address_t symaddr = LM_ADDRESS_BAD;
	
	mu_assert("failed to enumerate symbols", LM_EnumSymbolsDemangled(pmod, _LM_EnumSymbolsCallback, (lm_void_t *)&symaddr) == LM_TRUE);
	mu_assert("incorrect symbol address", symaddr == real_symbol_addr);
	mu_assert("function attempted to run with bad arguments (invalid pmod)", LM_EnumSymbolsDemangled(LM_NULLPTR, _LM_EnumSymbolsCallback, LM_NULLPTR) == LM_FALSE);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_EnumSymbolsDemangled(pmod, LM_NULLPTR, LM_NULLPTR) == LM_FALSE);
	
	return NULL;
}

char *test_LM_FindSymbolAddressDemangled(lm_module_t *pmod)
{
	lm_address_t symaddr = LM_ADDRESS_BAD;

	symaddr = LM_FindSymbolAddressDemangled(pmod, real_symbol);

	mu_assert("invalid symbol address", symaddr != LM_ADDRESS_BAD);
	mu_assert("incorrect symbol address", symaddr == real_symbol_addr);
	mu_assert("function attempted to run with bad arguments (invalid pmod)", LM_FindSymbolAddressDemangled(LM_NULLPTR, real_symbol) == LM_ADDRESS_BAD);
	mu_assert("function attempted to run with bad arguments (invalid callback)", LM_FindSymbolAddressDemangled(pmod, LM_NULLPTR) == LM_ADDRESS_BAD);
	
	return NULL;
}
