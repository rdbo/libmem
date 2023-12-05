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
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include "types.h"

int lua_LM_FindProcess(lua_State *L)
{
	lm_process_t *udata;
	const char *procname;

	procname = luaL_checkstring(L, 1);

	lua_create_lm_process(L);
	udata = (lm_process_t *)lua_touserdata(L, lua_gettop(L));

	if (LM_FindProcess((lm_string_t)procname, udata) != LM_TRUE) {
		lua_pushnil(L);
	}

	return 1;
}

int lua_LM_FindModule(lua_State *L)
{
	lm_module_t *udata;
	const char *modname;

	modname = luaL_checkstring(L, 1);

	lua_create_lm_module(L);
	udata = (lm_module_t *)lua_touserdata(L, lua_gettop(L));

	if (LM_FindModule((lm_string_t)modname, udata) != LM_TRUE) {
		lua_pushnil(L);
	}

	return 1;
}

int luaopen_libmem_lua(lua_State *L)
{
	luaL_Reg functions[] = {
		{ "LM_FindProcess", lua_LM_FindProcess },
		{ "LM_FindModule", lua_LM_FindModule },
		{ NULL, NULL }
	};

	lua_define_lm_process(L);
	lua_define_lm_module(L);

	luaL_register(L, "libmem_lua", functions);

	return 1;
}
