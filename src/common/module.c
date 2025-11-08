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
#include <string.h>

LM_API lm_bool_t LM_CALL
LM_EnumModules(lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					     lm_void_t   *arg),
	       lm_void_t          *arg)
{
	lm_process_t process;

	if (!callback)
		return LM_FALSE;

	if (!LM_GetProcess(&process))
		return LM_FALSE;
	
	return LM_EnumModulesEx(&process, callback, arg);
}

/********************************/

typedef struct {
	lm_string_t name;
	lm_size_t name_len;
	lm_bool_t match_path;
	lm_module_t *module_out;
} find_module_t;

lm_bool_t LM_CALL
find_module_callback(lm_module_t *module, lm_void_t *arg)
{
	find_module_t *parg = (find_module_t *)arg;

	if (parg->match_path) {
		lm_size_t len;

		len = strlen(module->path);
		if (len < parg->name_len)
			return LM_TRUE;

		/* Compare the last characters from the path against the name */
		if (!strcmp(&module->path[len - parg->name_len], parg->name)) {
			*parg->module_out = *module;
			return LM_FALSE;
		}
	} else {
		if (!strcmp(module->name, parg->name)) {
			*parg->module_out = *module;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_FindModule(lm_string_t  name,
	      lm_module_t *module_out)
{
	find_module_t arg;
	
	if (!name || !module_out)
		return LM_FALSE;
	
	module_out->size = 0;
	arg.name = name;
	arg.name_len = strlen(name);
	arg.module_out = module_out;
	arg.match_path = strchr(name, LM_PATHSEP) ? LM_TRUE : LM_FALSE;

	return LM_EnumModules(find_module_callback, (lm_void_t *)&arg) == LM_TRUE && module_out->size > 0 ?
		LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_FindModuleEx(const lm_process_t *process,
		lm_string_t         name,
		lm_module_t        *module_out)
{
	find_module_t arg;
	
	if (!process || !name || !module_out)
		return LM_FALSE;
	
	module_out->size = 0;
	arg.name = name;
	arg.name_len = strlen(name);
	arg.module_out = module_out;
	arg.match_path = strchr(name, LM_PATHSEP) ? LM_TRUE : LM_FALSE;

	return LM_EnumModulesEx(process, find_module_callback, (lm_void_t *)&arg) == LM_TRUE && module_out->size > 0 ?
		LM_TRUE : LM_FALSE;
}
