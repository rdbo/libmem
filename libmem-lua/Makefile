# NOTE: This should be replaced with a proper build system for Lua, and should be compatible with LuaRocks
# The current build method is only used for testing the initial bindings

all:
	mkdir -p build
	cc -o build/libmem_lua.so -shared -fPIC src/*.c -llibmem
