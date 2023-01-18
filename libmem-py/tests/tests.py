from libmem import *
import ctypes
import struct

def separator():
    print("========================================")

print("[*] libmem-py tests")

separator()

print("[*] Process Enumeration")
print("\n".join([str(proc) for proc in LM_EnumProcesses()[:5]]))

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

print(f"[*] Is Remote Process Alive? {'Yes' if LM_IsProcessAlive(proc) else 'No'}")

separator()

print(f"[*] System Bits: {LM_GetSystemBits()}")

separator()

print(f"[*] Current Process Threads: {LM_EnumThreads()}")

separator()

print(f"[*] Remote Process Threads: {LM_EnumThreadsEx(proc)}")

separator()

thread = LM_GetThread()
print(f"[*] Current Thread: {thread}")

separator()

print(f"[*] Remote Thread: {LM_GetThreadEx(proc)}")

separator()

print(f"[*] Process From Thread '{thread}': {LM_GetThreadProcess(thread)}")

separator()

print("[*] Module Enumeration - Current Process")
print("\n".join([str(mod) for mod in LM_EnumModules()[:5]]))

separator()

print("[*] Module Enumeration - Remote Process")
print("\n".join([str(mod) for mod in LM_EnumModulesEx(proc)[:5]]))

separator()

curmod = LM_FindModule(curproc.path)
print(f"[*] Current Process Module: {curmod}")

separator()

mod = LM_FindModuleEx(proc, proc.path)
print(f"[*] Remote Process Module: {mod}")

separator()

# TODO: Add tests for LM_LoadModule(Ex) and LM_UnloadModule(Ex)

# separator()

print("[*] Symbol Enumeration")

print("\n".join([str(sym) for sym in LM_EnumSymbols(curmod)[:5]]))

separator()

print("[*] Symbol Address Search")

symaddr = LM_FindSymbolAddress(curmod, "Py_BytesMain")
print(f"[*] Py_BytesMain Address: {symaddr}")

separator()

print("[*] Page Enumeration - Current Process")
print("\n".join([str(page) for page in LM_EnumPages()[:5]]))

separator()

print("[*] Page Enumeration - Remote Process")
print("\n".join([str(page) for page in LM_EnumPagesEx(proc)[:5]]))

separator()

print(f"[*] Page From Current Process Module: {LM_GetPage(symaddr)}")

separator()

print(f"[*] Page From Remote Process Module: {LM_GetPageEx(proc, mod.base)}")

separator()

val = ctypes.c_int(10)
val_addr = ctypes.addressof(val)
rdbuf = LM_ReadMemory(val_addr, ctypes.sizeof(val))
rdval = struct.unpack("@i", rdbuf)[0]
print(f"[*] Read Integer From '{hex(val_addr)}': {str(rdval)}")

separator()

# TODO: Add tests for 'LM_ReadMemoryEx'
# separator()

LM_WriteMemory(val_addr, bytearray(b"\x39\x05\x00\x00"))
print(f"[*] Integer After LM_WriteMemory: {val}")

separator()

# TODO: Add tests for 'LM_WriteMemoryEx'
# separator()

LM_SetMemory(val_addr, b"\x00", ctypes.sizeof(val))
print(f"[*] Integer After LM_SetMemory: {val}")

separator()

# TODO: Add tests for 'LM_SetMemoryEx'
# separator()

print("[*] Changing Memory Protection - Current Process")
old_prot = LM_ProtMemory(curmod.base, 0x1000, LM_PROT_XRW)
print(f"[*] Old Memory Protection ({hex(curmod.base)}): {old_prot}")
page = LM_GetPage(curmod.base)
print(f"[*] Current Memory Protection ({hex(curmod.base)}): {page.prot}")

separator()

print("[*] Changing Memory Protection - Remote Process")
old_prot = LM_ProtMemoryEx(proc, mod.base, 0x1000, LM_PROT_XRW)
print(f"[*] Old Memory Protection ({hex(mod.base)}): {old_prot}")
page = LM_GetPageEx(proc, mod.base)
print(f"[*] Current Memory Protection ({hex(mod.base)}): {page.prot}")

separator()

alloc_size = 0x1000
alloc = LM_AllocMemory(alloc_size, LM_PROT_XRW)
print(f"[*] Allocated Memory - Current Process: {hex(alloc)}")
LM_FreeMemory(alloc, alloc_size)

separator()

alloc = LM_AllocMemoryEx(proc, alloc_size, LM_PROT_XRW)
print(f"[*] Allocated Memory - Remote Process: {hex(alloc)}")
LM_FreeMemoryEx(proc, alloc, alloc_size)

separator()

buf = ctypes.c_buffer(b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0")
buf_addr = ctypes.addressof(buf)
print(f"[*] Scanning For Buffer At: {hex(buf_addr)}")
scan_addr = buf_addr - 0x10
scan_size = 0x100
data_scan = LM_DataScan(bytearray(buf.value), scan_addr, scan_size)
print(f"[*] Data Scan Match: {hex(data_scan)}")
pattern_scan = LM_PatternScan(bytearray(buf.value), "xxxx?x?x?x", scan_addr, scan_size)
print(f"[*] Pattern Scan Match: {hex(pattern_scan)}")
sig_scan = LM_SigScan("10 20 30 40 ?? ?? 70 80 ?? A0", scan_addr, scan_size)
print(f"[*] Signature Scan Match: {hex(sig_scan)}")

separator()

# TODO: Add tests for 'LM_DataScanEx', 'LM_PatternScanEx', 'LM_SigScanEx'
# separator()

# TODO: Add tests for 'LM_HookCode' and 'LM_UnhookCode'
# separator()

# TODO: Add tests for 'LM_HookCodeEx' and 'LM_UnhookCodeEx'
# separator()

print("[*] Assemblying Instruction")
inst = LM_Assemble("mov eax, ebx")
print(inst)

separator()

print("[*] Assemblying Instructions")
insts = LM_AssembleEx("push ebp; mov ebp, esp; mov esp, ebp; pop ebp; ret", 32, 0)
print(", ".join([hex(b) for b in insts]))

separator()

print("[*] Disassembly of PyBytesMain")
inst = LM_Disassemble(symaddr)
print(inst)

separator()

minlength = 0x5
aligned_length = LM_CodeLength(symaddr, 0x5)
print(f"[*] Aligned Length for Minimum '{minlength}' Bytes is '{aligned_length}' Bytes (PyBytesMain)")

separator()

# TODO: Add tests for 'LM_CodeLengthEx'

