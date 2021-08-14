from libmem import *

def enum_processes_callback(pid : lm_pid_t, arg):
	print(f"[*] CurPID: {int(pid)}")
	return 1


pid = LM_GetProcessIdEx("test1")
ppid = LM_GetParentIdEx(pid)
proc = LM_OpenProcessEx(pid)
procpath = LM_GetProcessPathEx(proc)
procname = LM_GetProcessNameEx(proc)
procbits = LM_GetProcessBitsEx(proc)
sysbits = LM_GetSystemBits()
LM_EnumProcesses(enum_processes_callback, None)
print(f"[*] PID: {proc.pid}")
print(f"[*] PPID: {int(ppid)}")
print(f"[*] Process Path: {procpath}")
print(f"[*] Process Name: {procname}")
print(f"[*] Process Bits: {procbits}")
print(f"[*] System Bits: {sysbits}")
LM_CloseProcess(proc)
