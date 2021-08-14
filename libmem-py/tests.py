from libmem import *

class counter:
	def __init__(self):
		self.value = 0
	
	def inc(self):
		self.value += 1
	
	def dec(self):
		self.value -= 1
	
	def val(self):
		return self.value

def counter_callback_pid(pid : lm_pid_t, arg) -> int:
	arg.inc()
	return LM_TRUE

def counter_callback_tid(tid : lm_tid_t, arg) -> int:
	arg.inc()
	return LM_TRUE

def counter_callback_mod(mod : lm_module_t, path : str, arg) -> int:
	arg.inc()
	return LM_TRUE

print("[+] PyTest 1")
nprocs = counter()
LM_EnumProcesses(counter_callback_pid, nprocs)
print(f"[*] Processes: {nprocs.val()}")

pid = LM_GetProcessId()
ppid = LM_GetParentId()
print(f"[*] PID: {int(pid)}")
print(f"[*] PPID: {int(ppid)}")

nthreads = counter()
LM_EnumThreads(counter_callback_tid, nthreads)
print(f"[*] Threads: {nthreads.val()}")

tid = LM_GetThreadId()
print(f"[*] TID: {int(tid)}")

proc = LM_OpenProcess()
procpath = LM_GetProcessPath()
procname = LM_GetProcessName()
procbits = LM_GetProcessBits()
print(f"[*] Process ID: {proc.pid}")
print(f"[*] Process Path: {procpath}")
print(f"[*] Process Name: {procname}")
print(f"[*] Process Bits: {procbits}")

sysbits = LM_GetSystemBits()
print(f"[*] System Bits: {sysbits}")

print("====================")

nmods = counter()
LM_EnumModules(counter_callback_mod, nmods)
print(f"[*] Modules: {nmods.val()}")

mod = LM_GetModule(LM_MOD_BY_STR, procpath)
mod = LM_GetModule(LM_MOD_BY_ADDR, mod.base)
modpath = LM_GetModulePath(mod)
modname = LM_GetModuleName(mod)
print(f"[*] Module Base: {hex(mod.base)}")
print(f"[*] Module End:  {hex(mod.end)}")
print(f"[*] Module Size: {hex(mod.size)}")
print(f"[*] Module Path: {modpath}")
print(f"[*] Module Name: {modname}")

LM_CloseProcess(proc)
print("[-] PyTest 1")
