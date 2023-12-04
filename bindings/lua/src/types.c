/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
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

int lua_lm_process_index(lua_State *L)
{
	lua_pushinteger(L, 1337);
	return 1;
}

int lua_lm_process_tostring(lua_State *L)
{
	lm_process_t *udata = (lm_process_t *)luaL_checkudata(L, 1, "lm_process_t");

	lua_pushfstring(L, "lm_process_t(pid: %d, ppid: %d, bits: %d, name: \"%s\", path: \"%s\", start_time: %p)", udata->pid, udata->ppid, udata->bits, udata->name, udata->path, udata->start_time);

	return 1;
}

void lua_create_lm_process(lua_State *L)
{
	lm_process_t *udata = lua_newuserdata(L, sizeof(lm_process_t));
	luaL_getmetatable(L, "lm_process_t");
	lua_setmetatable(L, lua_gettop(L) - 1);
}

void lua_define_lm_process(lua_State *L)
{
	luaL_newmetatable(L, "lm_process_t");
	lua_pushcfunction(L, lua_lm_process_index);
	lua_setfield(L, lua_gettop(L) - 1, "__index");
	lua_pushcfunction(L, lua_lm_process_tostring);
	lua_setfield(L, lua_gettop(L) - 1, "__tostring");
}
