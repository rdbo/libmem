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
#include <elfutils/elfutils.h>

typedef struct {
	lm_bool_t (LM_CALL *callback)(lm_symbol_t *, lm_void_t *);
	lm_void_t *arg;
} enum_symbols_t;

int
enum_symbols_callback(char *name, uint64_t address, void *arg)
{
	enum_symbols_t *parg = (enum_symbols_t *)arg;
	lm_symbol_t symbol;

	symbol.name = (lm_string_t)name;
	symbol.address = (lm_address_t)address;

	if (parg->callback(&symbol, parg->arg) == LM_FALSE)
		return 0;
	
	return 1;
}

LM_API lm_bool_t LM_CALL
LM_EnumSymbols(const lm_module_t  *module,
	       lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
					     lm_void_t   *arg),
	       lm_void_t          *arg)
{
	enum_symbols_t parg;
	
	if (!module || !callback)
		return LM_FALSE;

	parg.callback = callback;
	parg.arg = arg;
	
	enum_elf_symbols(module->path, module->base, enum_symbols_callback, (lm_void_t *)&parg);
	
	return LM_TRUE;
}
