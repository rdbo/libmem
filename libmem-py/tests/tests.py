from libmem import *

def separator():
    print("========================================")

print("[*] libmem-py tests")
separator()

print("[*] Process Enumeration")
proclist = LM_EnumProcesses()
for i in range(len(proclist)):
    if i >= 5:
        break
    print(proclist[i])

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
proc = LM_FindProcess("firefox-esr")
print(proc)

separator()

print("[*] Is Remote Process Alive? " + "Yes" if LM_IsProcessAlive(proc) else "No")

separator()

print("[*] System Bits: " + str(LM_GetSystemBits()))

separator()

