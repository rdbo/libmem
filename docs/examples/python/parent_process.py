from libmem import *

current_process = LM_GetProcess()
if current_process is None:
    print("[*] Failed to get current process")
    exit(-1)

print(f"[*] Process ID:          {current_process.pid}")
print(f"[*] Parent Process ID:   {current_process.ppid}")

parent_process = LM_GetProcessEx(current_process.ppid)
if parent_process is None:
    print("[*] Failed to get parent process")
    exit(-1)

print(f"[*] Parent Process Name: {parent_process.name}")
