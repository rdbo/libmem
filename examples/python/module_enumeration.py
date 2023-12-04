from libmem import *

for module in LM_EnumModules():
    print(f"[*] Module Base: {module.base}")
    print(f"[*] Module End:  {module.end}")
    print(f"[*] Module Size: {module.size}")
    print(f"[*] Module Name: {module.name}")
    print(f"[*] Module Path: {module.path}")
    print("====================")

