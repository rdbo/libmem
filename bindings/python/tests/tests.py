from libmem import *
import ctypes
import struct
import time
import os

def separator():
    print("========================================")

print("[*] libmem-py tests")

separator()

print("[*] Process Enumeration")
print("\n".join([str(proc) for proc in enum_processes()[:5]]))

separator()

print("[*] Current Process")
curproc = get_process()
print(curproc)

separator()

print("[*] Parent Process of Current Process")
parent_proc = get_process_ex(curproc.ppid)
print(parent_proc)

separator()

print("[*] Remote Process")
proc = find_process("target")
print(proc)

separator()

print(f"[*] Is Remote Process Alive? {'Yes' if is_process_alive(proc) else 'No'}")

separator()

print(f"[*] System Bits: {get_system_bits()}")

separator()

print(f"[*] Current Process Threads: {enum_threads()}")

separator()

print(f"[*] Remote Process Threads: {enum_threads_ex(proc)}")

separator()

thread = get_thread()
print(f"[*] Current Thread: {thread}")

separator()

print(f"[*] Remote Thread: {get_thread_ex(proc)}")

separator()

print(f"[*] Process From Thread '{thread}': {get_thread_process(thread)}")

separator()

print("[*] Module Enumeration - Current Process")
print("\n".join([str(mod) for mod in enum_modules()[:5]]))

separator()

print("[*] Module Enumeration - Remote Process")
print("\n".join([str(mod) for mod in enum_modules_ex(proc)[:5]]))

separator()

curmod = find_module(curproc.path)
print(f"[*] Current Process Module: {curmod}")

separator()

mod = find_module_ex(proc, proc.path)
print(f"[*] Remote Process Module: {mod}")

separator()

libpath = f"{os.path.dirname(os.path.realpath(__file__))}{os.sep}{os.pardir}{os.sep}{os.pardir}{os.sep}{os.pardir}{os.sep}build{os.sep}tests{os.sep}libtest.so"
print(f"[*] Loadable Library Path: {libpath}")
cur_loaded_mod = load_module(libpath)
print()
print(f"[*] Loaded Module into Current Process: {cur_loaded_mod}")

unload_module(cur_loaded_mod)
print("[*] Unloaded Module from Current Process")

separator()

loaded_mod = load_module_ex(proc, libpath)
print("[*] Loaded Module into Target Process: ", loaded_mod)

unload_module_ex(proc, loaded_mod)
print("[*] Unloaded Module from Target Process")

separator()

print("[*] Symbol Enumeration")

print("\n".join([str(sym) for sym in enum_symbols(curmod)[:5]]))

separator()

print("[*] Symbol Address Search")

symaddr = find_symbol_address(curmod, "Py_BytesMain")
if symaddr == None:
    symaddr = find_symbol_address(curmod, "_start_c")
print(f"[*] Py_BytesMain Address: {hex(symaddr)}")

separator()

mangled = "_Z15_enum_symbolsP11module_tPFiP11symbol_tPvES3_"
demangled = demangle_symbol(mangled)
print(f"[*] Demangled '{mangled}': {demangled}")

separator()

print("[*] Demangled Symbol Enumeration")

print("\n".join([str(sym) for sym in enum_symbols_demangled(curmod)[:5]]))

separator()

symaddr = find_symbol_address_demangled(curmod, "Py_BytesMain")
if symaddr == None:
    symaddr = find_symbol_address_demangled(curmod, "_start_c")
print(f"[*] Py_BytesMain Address (Demangled): {hex(symaddr)}")

separator()

print("[*] Segment Enumeration - Current Process")
print("\n".join([str(segment) for segment in enum_segments()[:5]]))

separator()

print("[*] Segment Enumeration - Remote Process")
print("\n".join([str(segment) for segment in enum_segments_ex(proc)[:5]]))

separator()

print(f"[*] Segment From Current Process Module: {find_segment(symaddr)}")

separator()

print(f"[*] Segment From Remote Process Module: {find_segment_ex(proc, mod.base)}")

separator()

val = ctypes.c_int(10)
val_addr = ctypes.addressof(val)
rdbuf = read_memory(val_addr, ctypes.sizeof(val))
rdval = struct.unpack("@i", rdbuf)[0]
print(f"[*] Read Integer From '{hex(val_addr)}': {str(rdval)}")

separator()

# TODO: Add tests for 'read_memory_ex'
# separator()

write_memory(val_addr, bytearray(b"\x39\x05\x00\x00"))
print(f"[*] Integer After write_memory: {val}")

separator()

# TODO: Add tests for 'write_memory_ex'
# separator()

set_memory(val_addr, b"\x00", ctypes.sizeof(val))
print(f"[*] Integer After set_memory: {val}")

separator()

# TODO: Add tests for 'set_memory_ex'
# separator()

print("[*] Changing Memory Protection - Current Process")
old_prot = prot_memory(curmod.base, 0x1000, PROT_XRW)
print(f"[*] Old Memory Protection ({hex(curmod.base)}): {old_prot}")
segment = find_segment(curmod.base)
print(f"[*] Current Memory Protection ({hex(curmod.base)}): {segment.prot}")

separator()

print("[*] Changing Memory Protection - Remote Process")
old_prot = prot_memory_ex(proc, mod.base, 0x1000, PROT_XRW)
print(f"[*] Old Memory Protection ({hex(mod.base)}): {old_prot}")
segment = find_segment_ex(proc, mod.base)
print(f"[*] Current Memory Protection ({hex(mod.base)}): {segment.prot}")

separator()

alloc_size = 0x1000
alloc = alloc_memory(alloc_size, PROT_XRW)
print(f"[*] Allocated Memory - Current Process: {hex(alloc)}")
free_memory(alloc, alloc_size)

separator()

alloc = alloc_memory_ex(proc, alloc_size, PROT_XRW)
print(f"[*] Allocated Memory - Remote Process: {hex(alloc)}")
free_memory_ex(proc, alloc, alloc_size)

separator()

addr0 = alloc_memory(4, PROT_RW)
addr1 = alloc_memory(8, PROT_RW)
addr2 = alloc_memory(8, PROT_RW)

write_memory(addr0, bytearray(b"\x10\x00\x00\x00"))
write_memory(addr1, bytearray(addr0.to_bytes(8, byteorder="little")))
write_memory(addr2, bytearray(addr1.to_bytes(8, byteorder="little")))
print("[*] Address 0: ", hex(addr0))
print("[*] Address 1: ", hex(addr1))
print("[*] Address 2: ", hex(addr2))

deep_ptr = deep_pointer(addr2, [0, 0])
print("[*] Deep Pointer result: " + hex(deep_ptr))

value = int.from_bytes(read_memory(deep_ptr, 4), byteorder="little")
print("[*] Deep Pointer value: " + hex(value))

separator()

buf = ctypes.c_buffer(b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0")
buf_addr = ctypes.addressof(buf)
print(f"[*] Scanning For Buffer At: {hex(buf_addr)}")
scan_addr = buf_addr - 0x10
scan_size = 0x100
data_scan = data_scan(bytearray(buf.value), scan_addr, scan_size)
print(f"[*] Data Scan Match: {hex(data_scan)}")
pattern_scan = pattern_scan(bytearray(buf.value), "xxxx?x?x?x", scan_addr, scan_size)
print(f"[*] Pattern Scan Match: {hex(pattern_scan)}")
sig_scan = sig_scan("10 20 30 40 ?? ?? 70 80 ?? A0", scan_addr, scan_size)
print(f"[*] Signature Scan Match: {hex(sig_scan)}")

separator()

scan_alloc = alloc_memory_ex(proc, 1024, PROT_RW)
print(f"[*] External Scan Alloc: {hex(scan_alloc)}")
buf_addr = scan_alloc + 0x10
write_memory_ex(proc, buf_addr, bytearray(buf.value))
print(f"[*] Externally Scanning For Buffer At: {hex(buf_addr)}")
scan_addr = buf_addr - 0x10
scan_size = 0x100
data_scan = data_scan_ex(proc, bytearray(buf.value), scan_addr, scan_size)
print(f"[*] Data Scan Match: {hex(data_scan)}")
pattern_scan = pattern_scan_ex(proc, bytearray(buf.value), "xxxx?x?x?x", scan_addr, scan_size)
print(f"[*] Pattern Scan Match: {hex(pattern_scan)}")
sig_scan = sig_scan_ex(proc, "10 20 30 40 ?? ?? 70 80 ?? A0", scan_addr, scan_size)
print(f"[*] Signature Scan Match: {hex(sig_scan)}")

# TODO: Add tests for 'hook_code' and 'unhook_code'
# separator()

wait_message_addr = find_symbol_address(mod, "wait_message")
hk_wait_message_addr = find_symbol_address(mod, "hk_wait_message")
trampoline = hook_code_ex(proc, wait_message_addr, hk_wait_message_addr)
print(f"[*] External Hook Trampoline: {trampoline}")
time.sleep(3)
unhook_code_ex(proc, wait_message_addr, trampoline)
print("[*] Unhooked External Function")

separator()

print("[*] Assemblying Instruction")
inst = assemble("mov eax, ebx")
print(inst)

separator()

print("[*] Assemblying Instructions")
insts = assemble_ex("push ebp; mov ebp, esp; mov esp, ebp; pop ebp; ret", ARCH_X86, 0)
print(", ".join([hex(b) for b in insts]))

separator()

print("[*] Disassembly of PyBytesMain Instruction")
inst = disassemble(symaddr)
print(inst)

separator()

print("[*] Disassembly of PyBytesMain Instructions")
insts = disassemble_ex(symaddr, ARCH_X86, 0x100, 5, symaddr)
print("\n".join([str(inst) for inst in insts]))

separator()

minlength = 0x5
aligned_length = code_length(symaddr, minlength)
print(f"[*] Aligned Length for Minimum '{minlength}' Bytes is '{aligned_length}' Bytes (PyBytesMain)")

separator()

# TODO: Add tests for 'code_length_ex'
# separator()

print("[*] VMT Hooking")

vtable = ctypes.c_ulonglong(0x1020304050607080)
vmt = Vmt(ctypes.addressof(vtable))
print(f"[*] Original Function: {hex(vmt.get_original(0))}")
vmt.hook(0, 0xdeadbeef)
print(f"[*] VMT After Hook: {hex(vtable.value)}")
vmt.unhook(0)
# vmt.reset()
print(f"[*] VMT After Unhook: {hex(vtable.value)}")

separator()

