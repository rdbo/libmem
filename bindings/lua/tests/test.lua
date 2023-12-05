print("Lua Tests")

function separator()
  print("====================")
end

local libmem = require("libmem_lua")
print("libmem_lua loaded")

target_proc = libmem.LM_FindProcess("target")
print("[*] Target Process")
print("PID: " .. target_proc.pid)
print("PPID: " .. target_proc.ppid)
print("Bits: " .. target_proc.bits)
print("Start Time: " .. target_proc.start_time)
print("Path: " .. target_proc.path)
print("Name: " .. target_proc.name)
print("(invalid): " .. (target_proc.invalid or "nil"))
print(target_proc)

separator()

mod = libmem.LM_FindModule("liblibmem.so")
print("[*] Find Module")
print("Base: " .. mod.base)
print("Size: " .. mod.size)
print("End: " .. mod["end"]) -- NOTE: mod.end won't work!
print("Path: " .. mod.path)
print("Name: " .. mod.name)
print("(invalid): " .. (mod.invalid or "nil"))
print(mod)
