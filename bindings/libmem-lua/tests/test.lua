print("Lua Tests")

local libmem = require("libmem_lua")
print("libmem_lua loaded")

print(libmem.LM_FindProcess("target"))
