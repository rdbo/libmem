![libmem-logo](https://raw.githubusercontent.com/rdbo/libmem/master/LOGO.png)  
### Made by rdbo
#  

## Discord Server
https://discord.com/invite/Qw8jsPD99X

## License
This project is licensed under the `GNU AGPLv3.0`
Read `LICENSE` for more information

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

    return 0;
}
```

### Rust
```rust
use libmem::*;

fn some_function() {
    // ...
}

fn hk_some_function() {
    // ...
}

fn main() {
    // reading/writing memory
    let number : i32 = 0;
    let number_addr = &number as *const i32 as lm_address_t;
    let value : i32 = 1337;
    LM_WriteMemory(number_addr, &value).unwrap(); // write 1337 to number
    let read_number : i32 = LM_ReadMemory(number_addr).unwrap();
    println!("[*] Number Value: {}", read_number); // it will show 1337

    // hooking/detouring functions
    let func_addr = some_function as *const () as lm_address_t;
    let hk_addr = hk_some_function as *const () as lm_address_t;
    println!("[*] Hooking 'some_function'");
    println!("[*] Original Address: {:#x}", func_addr);

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
```py
from libmem import *

# Assemble/Disassemble code
print("[*] Assembly")
inst = LM_Assemble("mov eax, ebx")
print(f"{code} : {inst.bytes}")

print("[*] Disassembly:")
inst = LM_Disassemble(bytearray(b"\x55"))
print(f"{inst.bytes} : {inst.mnemonic} {inst.op_str}")
```

## Installing

### Windows
**Note**: If you download a binary version of libmem in the GitHub releases, you only need to install the Windows SDK. Building is not necessary, just add `libmem/include` to your project's include directories and link it against the binary you downloaded.

- Install the Windows SDK: ![Windows 7](https://www.microsoft.com/en-us/download/details.aspx?id=8279) - ![Windows 10/11](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
- Install ![Visual Studio]() 2015 or newer (with C++ support and CMake)
- Install ![Git Bash](https://git-scm.com/downloads)
- Run `Git Bash`
- Continue reading at `Build and Install`

### Linux
**Note**: The following commands are for Debian/Ubuntu based distributions. Make sure to find the appropriate commands for your Linux distribution.

1. Open a terminal
2. Install GCC, G++, Git, CMake, and the Linux headers:

        ```
        sudo apt install gcc g++ git cmake linux-headers
        ```
3. Continue reading at `Build and Install`

### FreeBSD

1. Install GCC, G++, Git and CMake (run as root):

        ```
        pkg install gcc g++ git cmake
        ```
2. Continue reading at `Build and Install`

### Build and Install
**Note**: Run the following commands on Git Bash (Windows) or a terminal (Linux/FreeBSD).

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

Add `#include <libmem/libmem.h>` (C) or `#include <libmem/libmem.hpp>` (C++) to your source code.
Link the generated libmem library against your binary (`libmem.so` for Unix-like or `libmem.dll` for Windows).
*For GCC-like compilers*: add the flag `-lmem` to your compiler and it should link it.

## Usage (Rust)
Add the following line to your `Cargo.toml` under `[dependencies]`:
```toml
libmem = "0.1.0"
```
Import libmem in your Rust source code:
```rust
use libmem::*;
```

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
  
