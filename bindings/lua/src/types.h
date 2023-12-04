#ifndef TYPES_H
#define TYPES_H

#include <lua.h>

#define DECLTYPE(type) \
	void lua_create_##type(lua_State *L); \
	void lua_define_##type(lua_State *L);

DECLTYPE(lm_process)

#endif
