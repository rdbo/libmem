from libmem import *

pid = LM_GetProcessIdEx("test1")
proc = LM_OpenProcessEx(pid)
procpath = LM_GetProcessPathEx(proc)
procname = LM_GetProcessNameEx(proc)
bits = LM_GetProcessBitsEx(proc)
sysbits = LM_GetSystemBits()
print(f"[*] PID: {proc.pid}")
print(f"[*] Process Path: {procpath}")
print(f"[*] Process Name: {procname}")
print(f"[*] Process Bits: {bits}")
print(f"[*] System Bits: {sysbits}")
LM_CloseProcess(proc)
