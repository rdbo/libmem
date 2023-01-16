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
proc = LM_FindProcess("test1")
print(proc)

separator()

print("[*] Is Remote Process Alive? " + ("Yes" if LM_IsProcessAlive(proc) else "No"))

separator()

print("[*] System Bits: " + str(LM_GetSystemBits()))

separator()

print("[*] Current Process Threads: [" + ", ".join([str(thr) for thr in LM_EnumThreads()]) + "]")

separator()

print("[*] Remote Process Threads: [" + ", ".join([str(thr) for thr in LM_EnumThreadsEx(proc)]) + "]")

separator()

thread = LM_GetThread()
print("[*] Current Thread: " + str(thread))

separator()

print("[*] Remote Thread: " + str(LM_GetThreadEx(proc)))

separator()

print("[*] Process From Thread '" + str(thread) + "': " + str(LM_GetThreadProcess(thread)))

separator()

