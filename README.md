![libmem-logo](LOGO.png)  
Made by rdbo
#  

## Discord Server
https://discord.com/invite/Qw8jsPD99X

## License
Read `LICENSE`

## Examples

### C/C++
```c
#include <libmem/libmem.h>

int main()
{
	lm_module_t mod;
	lm_address_t main_sym;

	LM_FindModule("mygamemodule.so", &mod);
	main_sym = LM_FindSymbolAddress(&mod, "main");
	printf("[*] Module Name: %s\n", mod.name);
	printf("[*] Module Path: %s\n", mod.path);
	printf("[*] Module Base: %p\n", mod.base);
	printf("[*] Module Size: %p\n", mod.size);
	printf("[*] Module End:  %p\n", mod.end);
	printf("[*] Main Addr:   %p\n"), main_sym);
}
```

### Rust
```rust
fn some_function() {
    // ...
}

fn hk_some_function() {
    // ...
}

fn main() {
    let func_addr = some_function as *const () as lm_address_t;
    let hk_addr = hk_some_function as *const () as lm_address_t;
    println!("[*] Hooking 'some_function'");
    println!("[*] Original Address: {:#x}", func_addr;

    let trampoline = LM_HookCode(func_addr, hk_addr).unwrap();
    println!("[*] Trampoline: {:#x?}", trampoline);

    some_function(); // this will call 'hk_some_function'

    // restore the original code from 'some_function'
    LM_UnhookCode(some_function_addr, trampoline).unwrap();

    println!("[*] Unhooked 'some_function'");
    some_function(); // call 'some_function' to see if it has been unhooked
}

```

### Python
```

```

## Installing
Clone the repository:
```
git clone https://github.com/rdbo/libmem
```
Initialize and update the submodules:
```
git submodule init
git submodule update
```
Compile libmem:
```
mkdir build
cd build
cmake ..
make -j 4
```
Install libmem:
```
# Run as root
make install
```
After installing, follow the the proper `Usage` section for your programming language

## Usage (C/C++)

Add `#include <libmem/libmem.h>` (C) or `#include <libmem/libmem.hpp>` (C++) to your source code
Link the generated libmem library against your binary (`libmem.so`/`libmem.a` for Unix-like or `libmem.dll`/`libmem.lib` for Windows)

## Usage (Python)
Make sure to have Python >= 3.6 active  
Either install the `libmem` package from PyPi by running the following command:  
```
pip install --upgrade libmem
```
Or build and install it yourself by running the following commands:
```
cd libmem-py
python configure.py
python setup.py install
```
Now to import libmem, just do the following in your Python code:
```py
from libmem import *
```

## Dependencies
All:
- capstone (included in root project)
- keystone (included in root project)
- LIEF (included in root project)
- libstdc++ (used in keystone and LIEF)
- libmath (used in keystone)

Windows:  
- Windows SDK (-luser32, -lpsapi)  
  
Linux/Android:  
- libdl (-ldl)  
  
BSD:  
- libdl (-ldl)  
- libkvm (-lkvm)
- libprocstat (-lprocstat)    
- libelf (-lelf)
  
## API Overview
```
LM_EnumProcesses
LM_GetProcess
LM_FindProcess
LM_IsProcessAlive
LM_GetSystemBits

LM_EnumThreadIds
LM_EnumThreadIdsEx
LM_GetThreadId
LM_GetThreadIdEx

LM_EnumModules
LM_EnumModulesEx
LM_FindModule
LM_FindModuleEx
LM_LoadModule
LM_LoadModuleEx
LM_UnloadModule
LM_UnloadModuleEx

LM_EnumSymbols
LM_FindSymbolAddress

LM_EnumPages
LM_EnumPagesEx
LM_GetPage
LM_GetPageEx

LM_ReadMemory
LM_ReadMemoryEx
LM_WriteMemory
LM_WriteMemoryEx
LM_SetMemory
LM_SetMemoryEx
LM_ProtMemory
LM_ProtMemoryEx
LM_AllocMemory
LM_AllocMemoryEx
LM_FreeMemory
LM_FreeMemoryEx

LM_DataScan
LM_DataScanEx
LM_PatternScan
LM_PatternScanEx
LM_SigScan
LM_SigScanEx

LM_HookCode
LM_HookCodeEx
LM_UnhookCode
LM_UnhookCodeEx

LM_Assemble
LM_AssembleEx
LM_FreeCodeBuffer
LM_Disassemble
LM_DisassembleEx
LM_FreeInstructions
LM_CodeLength
LM_CodeLengthEx
```

## Projects
Made with libmem:  
- ![AssaultCube Multihack](https://github.com/rdbo/AssaultCube-Multihack)  
- ![X-Inject](https://github.com/rdbo/x-inject)  
- ![DirectX9 BaseHook](https://github.com/rdbo/DX9-BaseHook)  
- ![DirectX11 BaseHook](https://github.com/rdbo/DX11-BaseHook)  
- ![OpenGL BaseHook](https://github.com/rdbo/GL-BaseHook)  
- ![Counter-Strike 1.6 BaseHook](https://github.com/rdbo/cstrike-basehook)  
- ![Crazymem - NodeJS Memory Library](https://github.com/karliky/Crazymem)  
  
