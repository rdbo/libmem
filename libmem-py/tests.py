from libmem import *

pid = LM_GetProcessIdEx("test1")
proc = LM_OpenProcessEx(pid)
print(f"[*] PID: {proc.pid}")
LM_CloseProcess(proc)
