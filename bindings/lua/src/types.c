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

#define STREQUAL(a, b) (!strcmp(a, b))
#define LUA_ENTRY_INT(name) \
	if (STREQUAL(entry, #name)) { \
		lua_pushinteger(L, (lua_Integer)udata->name); \
		return 1; \
	}
#define LUA_ENTRY_STR(name) \
	if (STREQUAL(entry, #name)) { \
		lua_pushstring(L, udata->name); \
		return 1; \
	}
#define LM_PROCESS_META "lm_process_t"
#define LM_MODULE_META "lm_module_t"

/****************
 * lm_process_t *
 ***************/

int lua_lm_process_index(lua_State *L)
{
	lm_process_t *udata = (lm_process_t *)luaL_checkudata(L, 1, LM_PROCESS_META);
	const char *entry = luaL_checkstring(L, 2);

	LUA_ENTRY_INT(pid)
	LUA_ENTRY_INT(ppid)
	LUA_ENTRY_INT(bits)
	LUA_ENTRY_INT(start_time)
	LUA_ENTRY_STR(path)
	LUA_ENTRY_STR(name)

	lua_pushnil(L);
	return 1;
}

int lua_lm_process_tostring(lua_State *L)
{
	lm_process_t *udata = (lm_process_t *)luaL_checkudata(L, 1, LM_PROCESS_META);

	lua_pushfstring(L, "lm_process_t(pid: %d, ppid: %d, bits: %d, name: \"%s\", path: \"%s\", start_time: %p)", udata->pid, udata->ppid, udata->bits, udata->name, udata->path, udata->start_time);

	return 1;
}

void lua_create_lm_process(lua_State *L)
{
	lm_process_t *udata = (lm_process_t *)lua_newuserdata(L, sizeof(lm_process_t));
	luaL_getmetatable(L, LM_PROCESS_META);
	lua_setmetatable(L, lua_gettop(L) - 1);
}

void lua_define_lm_process(lua_State *L)
{
	luaL_newmetatable(L, LM_PROCESS_META);
	lua_pushcfunction(L, lua_lm_process_index);
	lua_setfield(L, lua_gettop(L) - 1, "__index");
	lua_pushcfunction(L, lua_lm_process_tostring);
	lua_setfield(L, lua_gettop(L) - 1, "__tostring");
}

/***************
 * lm_module_t *
 ***************/

int lua_lm_module_index(lua_State *L)
{
	lm_module_t *udata = (lm_module_t *)luaL_checkudata(L, 1, LM_MODULE_META);
	const char *entry = luaL_checkstring(L, 2);

	LUA_ENTRY_INT(base)
	LUA_ENTRY_INT(end)
	LUA_ENTRY_INT(size)
	LUA_ENTRY_STR(path)
	LUA_ENTRY_STR(name)

	lua_pushnil(L);
	return 1;
}

int lua_lm_module_tostring(lua_State *L)
{
	lm_module_t *udata = (lm_module_t *)luaL_checkudata(L, 1, LM_MODULE_META);

	lua_pushfstring(L, "lm_module_t(base: %p size: %p end: %p path: \"%s\" name: \"%s\")", udata->base, udata->size, udata->end, udata->path, udata->name);
	
	return 1;
}

void lua_create_lm_module(lua_State *L)
{
	lm_module_t *udata = (lm_module_t *)lua_newuserdata(L, sizeof(lm_module_t));
	luaL_getmetatable(L, LM_MODULE_META);
	lua_setmetatable(L, lua_gettop(L) - 1);
}

void lua_define_lm_module(lua_State *L)
{
	luaL_newmetatable(L, LM_MODULE_META);
	lua_pushcfunction(L, lua_lm_module_index);
	lua_setfield(L, lua_gettop(L) - 1, "__index");
	lua_pushcfunction(L, lua_lm_module_tostring);
	lua_setfield(L, lua_gettop(L) - 1, "__tostring");
}
