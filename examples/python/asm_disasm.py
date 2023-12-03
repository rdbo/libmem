from libmem import *
import ctypes

code_str = "push ebp; mov ebp, esp; mov esp, ebp; pop ebp; ret"
code_buf = LM_AssembleEx(code_str, 32, 0xdeadbeef)
if code_buf is None:
    print("[*] Failed to Assemble Instructions")
    exit(-1)

print("[*] Machine Code: ", code_buf)

code_buf = (ctypes.c_ubyte * len(code_buf))(*code_buf) # turn 'code_buf' into a C array

insts = LM_DisassembleEx(ctypes.addressof(code_buf), 32, len(code_buf), 0, 0xdeadbeef)
if insts is None:
    print("[*] Failed to Disassemble 'code_buf'")
    exit(-1)

print("[*] Disassembly of 'code_buf':")
for inst in insts:
    print("\t", inst)

