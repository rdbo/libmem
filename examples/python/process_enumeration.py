from libmem import *

for process in LM_EnumProcesses():
    print(f"[*] Process PID:  {process.pid}")
    print(f"[*] Process PPID: {process.ppid}")
    print(f"[*] Process Name: {process.name}")
    print(f"[*] Process Path: {process.path}")
    print(f"[*] Process Bits: {process.bits}")
    print("====================")

