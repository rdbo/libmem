from libmem import *

pid = LM_GetProcessIdEx("test1")
proc = LM_OpenProcessEx(pid)
procpath = LM_GetProcessPathEx(proc)
print(f"[*] PID: {proc.pid}")
print(f"[*] Process Path: {procpath}")
LM_CloseProcess(proc)
