from libmem import *
import ctypes
import struct

class counter:
	def __init__(self):
		self.value = 0
	
	def inc(self):
		self.value += 1
	
	def dec(self):
		self.value -= 1
	
	def val(self):
		return self.value

def counter_callback_pid(pid, arg) -> int:
	arg.inc()
	return LM_TRUE

def counter_callback_tid(tid, arg) -> int:
	arg.inc()
	return LM_TRUE

def counter_callback_mod(mod : lm_module_t, path : str, arg) -> int:
	arg.inc()
	return LM_TRUE

def counter_callback_sym(symbol : str, addr : int, arg):
	arg.inc()
	return LM_TRUE

def counter_callback_page(page : lm_page_t, arg):
	arg.inc()
	return LM_TRUE

print("[+] PyTest 1")
nprocs = counter()
LM_EnumProcesses(counter_callback_pid, nprocs)
print(f"[*] Processes: {nprocs.val()}")

pid = LM_GetProcessId()
ppid = LM_GetParentId()
print(f"[*] PID: {pid}")
print(f"[*] PPID: {ppid}")

nthreads = counter()
LM_EnumThreads(counter_callback_tid, nthreads)
print(f"[*] Threads: {nthreads.val()}")

tid = LM_GetThreadId()
print(f"[*] TID: {tid}")

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

print("====================")

nsyms = counter()
LM_EnumSymbols(mod, counter_callback_sym, nsyms)
print(f"[*] Symbols: {nsyms.val()}")

main_addr = LM_GetSymbol(mod, "Py_BytesMain")
print(f"[*] PyBytesMain Addr: {hex(main_addr)}")

print("====================")

npages = counter()
LM_EnumPages(counter_callback_page, npages)

print(f"[*] Pages: {npages.val()}")

page = LM_GetPage(mod.base)
print(f"[*] Page Base:  {hex(page.base)}")
print(f"[*] Page End:   {hex(page.end)}")
print(f"[*] Page Size:  {hex(page.size)}")
print(f"[*] Page Prot:  {page.prot}")
print(f"[*] Page Flags: {page.flags}")

print("====================")

val = ctypes.c_int(10)
val_addr = ctypes.addressof(val)
rdbuf = LM_ReadMemory(val_addr, ctypes.sizeof(val))
rdval = struct.unpack("@i", rdbuf)[0]
print(f"[*] Read Value:    {rdval}")

wrbuf = struct.pack("@i", 1337)
LM_WriteMemory(val_addr, wrbuf)
print(f"[*] Written Value: {val.value}")

setbuf = ctypes.c_buffer(b"NotSet")
setbuf_addr = ctypes.addressof(setbuf)

print(f"[*] Setbuf:         {setbuf.value} ")

LM_SetMemory(setbuf_addr, b"A", ctypes.sizeof(setbuf))
print(f"[*] Written Setbuf: {setbuf.value} ")

LM_CloseProcess(proc)
print("[-] PyTest 1")
