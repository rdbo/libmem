from libmem import *

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

print("[*] Current Process Module: " + str(LM_FindModule(curproc.path)))

separator()

print("[*] Remote Process Module: " + str(LM_FindModuleEx(proc, proc.path)))

separator()

# TODO: Add tests for LM_LoadModule(Ex) and LM_UnloadModule(Ex)

