from libmem import *

pid = LM_GetProcessIdEx("test1")
proc = LM_OpenProcessEx(pid)
procpath = LM_GetProcessPath()
print(f"[*] PID: {proc.pid}")
print(f"[*] Process Path: {procpath}")
LM_CloseProcess(proc)
