/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <libmem/libmem.h>
#include <demangler/demangler.h>
#include <string.h>

typedef struct {
	lm_string_t symbol_name;
	lm_address_t addr;
} find_symbol_t;

lm_bool_t LM_CALL
find_symbol_callback(lm_symbol_t *symbol, lm_void_t *arg)
{
	find_symbol_t *parg = (find_symbol_t *)arg;
	
	if (!strcmp(symbol->name, parg->symbol_name)) {
		parg->addr = symbol->address;
		return LM_FALSE;
	}

	return LM_TRUE;
}

LM_API lm_address_t LM_CALL
LM_FindSymbolAddress(const lm_module_t *module,
		     lm_string_t        symbol_name)
{
	find_symbol_t parg;

	if (!module || !symbol_name)
		return LM_FALSE;

	parg.symbol_name = symbol_name;
	parg.addr = LM_ADDRESS_BAD;

	LM_EnumSymbols(module, find_symbol_callback, (lm_void_t *)&parg);

	return parg.addr;
}

/********************************/

LM_API lm_char_t * LM_CALL
LM_DemangleSymbol(lm_string_t symbol_name,
		  lm_char_t  *demangled_buf,
		  lm_size_t   maxsize)
{
	if (!symbol_name)
		return LM_FALSE;
	
	return demangle(symbol_name, demangled_buf, maxsize);
}

/********************************/

LM_API lm_void_t LM_CALL
LM_FreeDemangledSymbol(lm_char_t *symbol_name)
{
	free(symbol_name);
}

/********************************/

typedef struct {
	lm_bool_t (LM_CALL *callback)(lm_symbol_t *, lm_void_t *);
	lm_void_t *arg;
} enum_demangled_t;

lm_bool_t LM_CALL
enum_symbols_demangled_callback(lm_symbol_t *symbol, lm_void_t *arg)
{
	enum_demangled_t *parg = (enum_demangled_t *)arg;
	lm_char_t *demangled;
	lm_symbol_t demangled_symbol;

	demangled = LM_DemangleSymbol(symbol->name, NULL, 0);
	if (!demangled)
		return LM_TRUE;

	demangled_symbol.name = (lm_string_t)demangled;
	demangled_symbol.address = symbol->address;

	parg->callback(&demangled_symbol, parg->arg);
	LM_FreeDemangledSymbol(demangled);
	
	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_EnumSymbolsDemangled(const lm_module_t  *module,
			lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
						      lm_void_t   *arg),
			lm_void_t          *arg)
{
	enum_demangled_t parg;

	if (!module || !callback)
		return LM_FALSE;

	parg.callback = callback;
	parg.arg = arg;
	
	return LM_EnumSymbols(module, enum_symbols_demangled_callback, (lm_void_t *)&parg);
}

/********************************/

LM_API lm_address_t
LM_FindSymbolAddressDemangled(const lm_module_t *module,
			      lm_string_t        symbol_name)
{
	find_symbol_t parg;

	if (!module || !symbol_name)
		return LM_ADDRESS_BAD;

	parg.symbol_name = symbol_name;
	parg.addr = LM_ADDRESS_BAD;

	LM_EnumSymbolsDemangled(module, find_symbol_callback, (lm_void_t *)&parg);

	return parg.addr;
}
