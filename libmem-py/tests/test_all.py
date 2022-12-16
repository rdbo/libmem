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

def counter_callback_pid(pid, arg) -> bool:
	arg.inc()
	return True

def counter_callback_tid(tid, arg) -> bool:
	arg.inc()
	return True

def counter_callback_mod(mod : lm_module_t, path : str, arg) -> bool:
	arg.inc()
	return True

def counter_callback_sym(symbol : str, addr : int, arg) -> bool:
	arg.inc()
	return True

def counter_callback_page(page : lm_page_t, arg) -> bool:
	arg.inc()
	return True

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

mod = LM_GetModule(procpath)
mod = LM_GetModule(mod.base)
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

alloc = LM_AllocMemory(10, LM_PROT_RW)
print(f"[*] Alloc:    {hex(alloc)}")

old_prot = LM_ProtMemory(mod.base, mod.size, LM_PROT_XRW)
cur_prot = LM_GetPage(mod.base).prot
print(f"[*] Prot:     {cur_prot}")
print(f"[*] Old Prot: {old_prot}")

LM_FreeMemory(alloc, 10)

print(f"[*] SetBuf Addr:  {hex(setbuf_addr)}")

data_scan = LM_DataScan(setbuf.value, setbuf_addr - 10, ctypes.sizeof(setbuf) + 10)
print(f"[*] Data Scan:    {hex(data_scan)}")

pattern_scan = LM_PatternScan(setbuf.value, "x" * ctypes.sizeof(setbuf),
			      setbuf_addr - 10, ctypes.sizeof(setbuf) + 10)
print(f"[*] Pattern Scan: {hex(pattern_scan)}")

sig = " ".join(["{:02X}".format(i) for i in setbuf.value]).replace("0x", "")
sig_scan = LM_SigScan(sig, setbuf_addr - 10, ctypes.sizeof(setbuf) + 10)
print(f"[*] Sig Scan:     {hex(sig_scan)}")

LM_CloseProcess(proc)

print("====================")

code = "mov eax, ebx"
print("[*] Assembly:")

inst = LM_Assemble(code, LM_ARCH_X86, 32)
print(f"{code} : {inst.bytes}")

print("[*] Disassembly:")
inst = LM_Disassemble(b"\x55", LM_ARCH_X86, 32)
print(f"{inst.bytes} : {inst.mnemonic} {inst.op_str}")

print("====================")

print("[-] PyTest 1")
print("********************")
print("[+] PyTest 2")

if LM_OS == LM_OS_WIN:
	pid = LM_GetProcessIdEx("test1.exe")
else:
	pid = LM_GetProcessIdEx("test1")

if pid is None:
	print("[!] test1 not running")
	print("[-] PyTest 2")
	exit()

ppid = LM_GetParentIdEx(pid)
print(f"[*] PID: {pid}")
print(f"[*] PPID: {ppid}")

proc = LM_OpenProcessEx(pid)

nthreads = counter()
LM_EnumThreadsEx(proc, counter_callback_tid, nthreads)
print(f"[*] Threads: {nthreads.val()}")

tid = LM_GetThreadIdEx(proc)
print(f"[*] TID: {tid}")

procchk  = LM_CheckProcess(proc.pid)
procpath = LM_GetProcessPathEx(proc)
procname = LM_GetProcessNameEx(proc)
procbits = LM_GetProcessBitsEx(proc)
print(f"[*] Process Check: {procchk}")
print(f"[*] Process ID: {proc.pid}")
print(f"[*] Process Path: {procpath}")
print(f"[*] Process Name: {procname}")
print(f"[*] Process Bits: {procbits}")

sysbits = LM_GetSystemBits()
print(f"[*] System Bits: {sysbits}")

print("====================")

nmods = counter()
LM_EnumModulesEx(proc, counter_callback_mod, nmods)
print(f"[*] Modules: {nmods.val()}")

mod = LM_GetModuleEx(proc, procpath)
mod = LM_GetModuleEx(proc, mod.base)
modpath = LM_GetModulePathEx(proc, mod)
modname = LM_GetModuleNameEx(proc, mod)
print(f"[*] Module Base: {hex(mod.base)}")
print(f"[*] Module End:  {hex(mod.end)}")
print(f"[*] Module Size: {hex(mod.size)}")
print(f"[*] Module Path: {modpath}")
print(f"[*] Module Name: {modname}")

print("====================")

nsyms = counter()
LM_EnumSymbolsEx(proc, mod, counter_callback_sym, nsyms)
print(f"[*] Symbols: {nsyms.val()}")

main_addr = LM_GetSymbolEx(proc, mod, "main")
val_addr  = LM_GetSymbolEx(proc, mod, "val")
print(f"[*] Main Addr: {hex(main_addr)}")
print(f"[*] Val Addr: {hex(val_addr)}")

print("====================")

npages = counter()
LM_EnumPagesEx(proc, counter_callback_page, npages)

print(f"[*] Pages: {npages.val()}")

page = LM_GetPageEx(proc, mod.base)
print(f"[*] Page Base:  {hex(page.base)}")
print(f"[*] Page End:   {hex(page.end)}")
print(f"[*] Page Size:  {hex(page.size)}")
print(f"[*] Page Prot:  {hex(page.prot)}")
print(f"[*] Page Flags: {hex(page.flags)}")

print("====================")

rdbuf = LM_ReadMemoryEx(proc, val_addr, 4)
rdval = struct.unpack("@i", rdbuf)[0]
print(f"[*] Read Value:    {rdval}")

wrbuf = struct.pack("@i", 69420)
LM_WriteMemoryEx(proc, val_addr, wrbuf)
rdbuf = LM_ReadMemoryEx(proc, val_addr, 4)
rdval = struct.unpack("@i", rdbuf)[0]
print(f"[*] Written Value: {rdval}")

setbuf_str = b"NotSet"
alloc = LM_AllocMemoryEx(proc, 10 + len(setbuf_str) + 10, LM_PROT_RW)
setbuf_addr = alloc + 10
LM_WriteMemoryEx(proc, setbuf_addr, setbuf)

print(f"[*] SetBuf:         {setbuf_str}")
LM_SetMemoryEx(proc, setbuf_addr, b"A", len(setbuf_str))
setbuf_str = LM_ReadMemoryEx(proc, setbuf_addr, len(setbuf_str))
print(f"[*] Written SetBuf: {setbuf_str}")

print(f"[*] Alloc: {hex(alloc)}")
old_prot = LM_ProtMemoryEx(proc, mod.base, mod.size, LM_PROT_XRW)
cur_prot = LM_GetPageEx(proc, mod.base).prot

print(f"[*] SetBuf Addr:  {hex(setbuf_addr)}")

data_scan = LM_DataScanEx(proc, setbuf_str, setbuf_addr - 10, len(setbuf_str) + 10)
print(f"[*] Data Scan:    {hex(data_scan)}")

pattern_scan = LM_PatternScanEx(proc, setbuf_str, "x" * len(setbuf_str), setbuf_addr - 10, len(setbuf_str) + 10)
print(f"[*] Pattern Scan: {hex(pattern_scan)}")

sig = " ".join(["{:02X}".format(i) for i in setbuf_str]).replace("0x", "")
sig_scan = LM_SigScanEx(proc, sig, setbuf_addr - 10, len(setbuf_str) + 10)
print(f"[*] Sig Scan:     {hex(sig_scan)}")

LM_FreeMemoryEx(proc, alloc, len(setbuf_str))

print(f"[*] Prot:     {cur_prot}")
print(f"[*] Old Prot: {old_prot}")

LM_CloseProcess(proc)

print("====================")

print("[-] PyTest 2")
