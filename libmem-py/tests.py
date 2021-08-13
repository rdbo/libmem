from libmem import *

pid = LM_GetProcessId()
proc = LM_OpenProcessEx(pid)
print(f"[*] PID: {proc.pid}")
LM_CloseProcess(proc)
print(f"[*] PID: {proc.pid}")
