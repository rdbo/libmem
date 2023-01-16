from libmem import *
import ctypes
import struct

def separator():
    print("========================================")

print("[*] libmem-py tests")

separator()

print("[*] Process Enumeration")
print("\n".join([str(proc) for proc in LM_EnumProcesses()[:5]]))

separator()

print("[*] Current Process")
curproc = LM_GetProcess()
print(curproc)

separator()

print("[*] Parent Process of Current Process")
parent_proc = LM_GetProcessEx(curproc.ppid)
print(parent_proc)

separator()

print("[*] Remote Process")
proc = LM_FindProcess("test1")
print(proc)

separator()

print("[*] Is Remote Process Alive? " + ("Yes" if LM_IsProcessAlive(proc) else "No"))

separator()

print("[*] System Bits: " + str(LM_GetSystemBits()))

separator()

print("[*] Current Process Threads: " + str(LM_EnumThreads()))

separator()

print("[*] Remote Process Threads: " + str(LM_EnumThreadsEx(proc)))

separator()

thread = LM_GetThread()
print("[*] Current Thread: " + str(thread))

separator()

print("[*] Remote Thread: " + str(LM_GetThreadEx(proc)))

separator()

print("[*] Process From Thread '" + str(thread) + "': " + str(LM_GetThreadProcess(thread)))

separator()

print("[*] Module Enumeration - Current Process")
print("\n".join([str(mod) for mod in LM_EnumModules()[:5]]))

separator()

print("[*] Module Enumeration - Remote Process")
print("\n".join([str(mod) for mod in LM_EnumModulesEx(proc)[:5]]))

separator()

curmod = LM_FindModule(curproc.path)
print("[*] Current Process Module: " + str(curmod))

separator()

mod = LM_FindModuleEx(proc, proc.path)
print("[*] Remote Process Module: " + str(mod))

separator()

# TODO: Add tests for LM_LoadModule(Ex) and LM_UnloadModule(Ex)

# separator()

print("[*] Symbol Enumeration")

print("\n".join([str(sym) for sym in LM_EnumSymbols(curmod)[:5]]))

separator()

print("[*] Symbol Address Search")

symaddr = LM_FindSymbolAddress(curmod, "Py_BytesMain")
print("[*] Py_BytesMain Address: " + hex(symaddr))

separator()

print("[*] Page Enumeration - Current Process")
print("\n".join([str(page) for page in LM_EnumPages()[:5]]))

separator()

print("[*] Page Enumeration - Remote Process")
print("\n".join([str(page) for page in LM_EnumPagesEx(proc)[:5]]))

separator()

print("[*] Page From Current Process Module: " + str(LM_GetPage(symaddr)))

separator()

print("[*] Page From Remote Process Module: " + str(LM_GetPageEx(proc, mod.base)))

separator()

val = ctypes.c_int(10)
val_addr = ctypes.addressof(val)
rdbuf = LM_ReadMemory(val_addr, ctypes.sizeof(val))
rdval = struct.unpack("@i", rdbuf)[0]
print(f"[*] Read Integer From '{hex(val_addr)}': {rdval}")

separator()

LM_WriteMemory(val_addr, bytearray(b"\x39\x05\x00\x00"))
print(f"[*] Integer After LM_WriteMemory: {val}")

separator()

