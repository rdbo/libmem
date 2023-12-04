from libmem import *
import ctypes
import struct

some_var = ctypes.c_int(10)
print("[*] Value of 'some_var':", some_var)

some_var_addr = ctypes.addressof(some_var)
read_some_var = LM_ReadMemory(some_var_addr, ctypes.sizeof(some_var))
read_some_var = struct.unpack("@i", read_some_var)[0] # unpack read bytes into an integer
print("[*] Read Value of 'some_var':", read_some_var)

LM_WriteMemory(some_var_addr, bytearray(b"\x39\x05\x00\x00"))
print("[*] Value of 'some_var' after writing:", some_var)

