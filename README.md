![libmem-logo](https://raw.githubusercontent.com/rdbo/libmem/master/LOGO.png)  
### Advanced Game Hacking Library (C/C++/Rust/Python) (Windows/Linux/FreeBSD)
### Made by rdbo
#  

## Discord Server
https://discord.com/invite/Qw8jsPD99X

## License
This project is licensed under the `GNU AGPLv3.0` (no later versions)

Read `LICENSE` for more information

**NOTE:** Submodules and external dependencies might have their own licenses! Check for their licenses as well.

## Platforms
|OS|x86|x64|ARM|Aarch64|
|:--:|:---:|:---:|:---:|:-------:|
|Windows|:white_check_mark:|:white_check_mark:|:warning:|:warning:|
|Linux|:white_check_mark:|:white_check_mark:|:warning:|:warning:|
|FreeBSD|:heavy_check_mark:|:heavy_check_mark:|:warning:|:warning:|

|Status|Description|
|:------:|:-----------:|
|:white_check_mark:|100% working|
|:heavy_check_mark:|Mostly working|
|:warning:|Untested|

## Features
- [x] Internal and External
- [x] Find and Enumerate Processes, Modules, Symbols, Threads and Segments
- [x] Read/Write Memory
- [x] Allocate/Protect Memory
- [x] Scan Memory by Pattern/Signature
- [x] Resolve Pointer Scans/Pointer Maps
- [x] Hook/Unhook Functions
- [x] Assemble/Disassemble Code (JIT)
- [x] VMT Hooking/Unhooking
- [x] Load/Unload Modules
- [x] Enumerate Process Threads

***And much more!***

## Examples
### Modern C++
```cpp
/* C++20 or higher */
#include <libmem/libmem.hpp>
#include <iostream>

using namespace libmem;

int main()
{
	Address disas_addr = reinterpret_cast<Address>(main);

	// Disassemble function 'main' until a 'ret' is found
	for (;;) {
		auto inst = Disassemble(disas_addr).value();
		std::cout << inst.to_string() << std::endl;
		if (inst.mnemonic == "ret")
			break;
		disas_addr += inst.bytes.size();
	}

	return 0;
}

/*
Output:
0x55b1a3259275: push rbp -> [ 55 ]
0x55b1a3259276: mov rbp, rsp -> [ 48 89 e5 ]
...
0x55b1a325941a: leave  -> [ c9 ]
0x55b1a325941b: ret  -> [ c3 ]
*/
```

### C/C++
```c
#include <libmem/libmem.h>

void hk_take_damage(int amount)
{
  printf("hooked take_damage! no damage will be taken\n");
  return;
}

int main()
{
	lm_module_t game_mod;
	lm_address_t fn_take_damage;

	LM_FindModule("game.dll", &game_mod);
	printf("[*] Base address of 'game.dll': %p\n", game_mod.base);

	fn_take_damage = LM_FindSymbolAddress(&game_mod, "take_damage");
	printf("[*] Found 'take_damage' function: %p\n", fn_take_damage);

	LM_HookCode(fn_take_damage, hk_take_damage, LM_NULLPTR);
	printf("[*] 'take_damage' hooked, player will no longer receive damage\n");

	return 0;
}
```

### Rust
```rust
use libmem::*;

fn godmode() -> Option<()> {
    let game_process = find_process("game_linux64")?;
    let client_module = find_module_ex(&game_process, "libclient.so")?;

    let fn_update_health = sig_scan_ex(
        &game_process,
        "55 48 89 E5 66 B8 ?? ?? 48 8B 5D FC",
        client_module.base,
        client_module.size,
    )?;
    println!(
        "[*] Signature scan result for 'update_health' function: {}",
        fn_update_health
    );

    let shellcode = assemble_ex("mov rbx, 1337; mov [rdi], rbx; ret", Arch::X64, 0)?;
    write_memory_ex(&game_process, fn_update_health + 8, &shellcode.as_slice())?;
    println!("[*] Patched 'update_health' function to always set health to 1337!");

    Some(())
}

fn main() {
    godmode();
}
```

### Python
```py
from libmem import *
import time

process = find_process("game.exe")
game_mod = find_module_ex(process, process.name)

# Resolve a Cheat Engine pointer scan
health_pointer = deep_pointer_ex(process, game_mod.base + 0xdeadbeef, [0xA0, 0x04, 0x10, 0xF0, 0x0])

# Set player health to 1337 forever
while True:
    write_memory_ex(process, health_pointer, bytearray(int(1337).to_bytes(4)))
    time.sleep(0.2)
```

## Documentation
The main documentation for libmem can be found in `include/libmem.h`.
All APIs are documented and contain very descriptive information about each function, their parameters and return value.
They are located in nearby comments, so you should be able to see them by hovering on your text editor/IDE.

Similarly, the bindings documentation is embedded with their packages, so your text editor/IDE should be able to access the documentation for each API.

## Unofficial Bindings
These bindings are done by the community/third-parties and are not affiliated with the libmem project or its author.

Their code can have their own licenses as well, diverging from libmem's.

- [Nim_Libmem](https://github.com/Hypnootika/python_nim_libmem)
- [Crazymem (NodeJS)](https://github.com/karliky/Crazymem)

## CMake Usage (without installing)
Add the following commands to your `CMakeLists.txt`.

They will fetch `libmem-config.cmake` from the root of this repository, which will download libmem binaries for your system and include libmem in your CMake project.

```cmake
include(FetchContent)

# Download and set up libmem
FetchContent_Declare(libmem-config URL "https://raw.githubusercontent.com/rdbo/libmem/config-v1/libmem-config.cmake" DOWNLOAD_NO_EXTRACT TRUE)
FetchContent_MakeAvailable(libmem-config)
set(CMAKE_PREFIX_PATH "${libmem-config_SOURCE_DIR}" "${CMAKE_PREFIX_PATH}")
set(LIBMEM_DOWNLOAD_VERSION "5.1.1")

# Find libmem package
find_package(libmem CONFIG REQUIRED)
```

Use the following to link against libmem (NOTE: it might be necessary to link against other dependencies - go to the `Dependencies` section for more information):

```cmake
# Link against libmem
target_link_libraries(<YOUR_TARGET_NAME> PRIVATE libmem::libmem)
```

## Installing

### vcpkg

[![vcpkg](https://img.shields.io/vcpkg/v/libmem)](https://vcpkg.io/en/package/libmem)

**Note**: Support vcpkg for package management

1. Install vcpkg (https://github.com/microsoft/vcpkg)

2. Run the following command to install the libmem package:

```
vcpkg install libmem
```

For detailed commands on installing different versions and more information, please refer to Microsoft's official instructions (https://learn.microsoft.com/en-us/vcpkg/get_started/overview)

### Windows
**Note**: If you download a binary version of libmem in the GitHub releases, you only need to install the Windows SDK. Building is not necessary, just add `libmem/include` to your project's include directories and link it against the binary you downloaded.

1. Install the Windows SDK: [Windows 7](https://www.microsoft.com/en-us/download/details.aspx?id=8279) - [Windows 10/11](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)

2. Install [Python 3](https://python.org/downloads) (Check the option to add Python to PATH) (Use [Python 3.8.9](https://python.org/downloads/release/python-389) for Windows 7)

3. Install [Visual Studio](https://visualstudio.microsoft.com/) 2022 or newer (with C++ support and CMake) (older versions might work, but they were not tested). NOTE: You can install only the Visual Studio Build Tools if you don't want the whole IDE.

4. Install [Git Bash](https://git-scm.com/downloads)

5. Run a Visual Studio `Developer Command Prompt` (or `x64 Native Tools Command Prompt for VS 2022` for 64 bits) as Administrator

6. Run the following command to append libmem's destination directory to your `%PATH%` user variable (**WARNING** - watch for your `%PATH%` size limit!):

        setx PATH "%PATH%;%ProgramFiles%\libmem\include;%ProgramFiles%\libmem\lib"

7. Continue reading at `Build and Install`

### Linux
**Note**: The following commands are for Debian/Ubuntu based distributions. Make sure to find the appropriate commands for your Linux distribution.

1. Open a terminal

2. Install GCC, G++, Git, CMake, Make, Python 3, and the Linux headers:

        sudo apt install gcc g++ git cmake make python3 linux-headers

3. Continue reading at `Build and Install`

### FreeBSD

1. Add a mountpoint for the `procfs` filesystem in your `/etc/fstab` by appending the following line:

        proc		/proc		procfs	rw	0	0

2. Manually mount the `procfs`. This will only be necessary if you don't reboot. If you reboot, it will be automatically mounted because of the line at `/etc/fstab`. Run the following command (as root):

        mount -t procfs proc /proc

3. Install Git, CMake and Python3 (run as root) (clang, clang++ and make should already be installed):

        pkg install git cmake python3

4. Continue reading at `Build and Install`

### Build and Install
**Note**: Run the following commands on Git Bash (Windows) or a terminal (Linux/FreeBSD).

Clone the repository:
```
git clone --recursive --depth 1 https://github.com/rdbo/libmem
```
Generate the CMake cache:
```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS=-fpermissive -DCMAKE_EXPORT_COMPILE_COMMANDS=1
```

Compile libmem:

*Windows*: `nmake`

*Unix-like*: `make -j 4`

Install libmem (run as root or as Administrator):

*Windows*: `nmake install`

*Unix-like*: `make install`

After installing, follow the the proper `Usage` section for your programming language

## Usage (C/C++)

Add `#include <libmem/libmem.h>` (C/C++) or `#include <libmem/libmem.hpp>` (C++) to your source code.
Link the generated libmem library against your binary (`liblibmem.so` for Unix-like or `libmem.dll` for Windows).
*For GCC-like compilers*: add the flag `-llibmem` to your compiler and it should link it.
```c
#include <libmem/libmem.h> /* C/C++ */
#include <libmem/libmem.hpp> /* Force C++ */
```

## Usage (Rust)
**NOTE**: You no longer have to install libmem to use with Rust, as long as the `fetch` feature is enabled on the libmem crate (default). If you disable that feature, it will look for libmem in your system, and you can make the libmem path explicit by using the environment var `LIBMEM_DIR=<path to libmem's directory>`.

Add the following line to your `Cargo.toml` under `[dependencies]`:
```toml
libmem = "5"
```
Import libmem in your Rust source code:
```rust
use libmem::*;
```

## Usage (Python)
**NOTE**: You no longer have to install libmem to use with Python. If no installation is found, the package will fetch and link libmem for you seamlessly. You can use the `LIBDIR=<path to libmem's directory>` environment variable to tell the libmem package where to look for your installation (if you installed it).

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
- libstdc++ (used in keystone, LIEF and LLVM)
- libmath (used in keystone)

Windows:  
- Windows SDK (user32.lib, psapi.lib, ntdll.lib, shell32.lib)

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
LM_GetProcessEx
LM_FindProcess
LM_IsProcessAlive
LM_GetBits
LM_GetSystemBits

LM_EnumThreads
LM_EnumThreadsEx
LM_GetThread
LM_GetThreadEx
LM_GetThreadProcess

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
LM_DemangleSymbol
LM_FreeDemangledSymbol
LM_EnumSymbolsDemangled
LM_FindSymbolAddressDemangled

LM_EnumSegments
LM_EnumSegmentsEx
LM_FindSegment
LM_FindSegmentEx

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
LM_DeepPointer
LM_DeepPointerEx

LM_DataScan
LM_DataScanEx
LM_PatternScan
LM_PatternScanEx
LM_SigScan
LM_SigScanEx

LM_GetArchitecture
LM_Assemble
LM_AssembleEx
LM_FreePayload
LM_Disassemble
LM_DisassembleEx
LM_FreeInstructions
LM_CodeLength
LM_CodeLengthEx

LM_HookCode
LM_HookCodeEx
LM_UnhookCode
LM_UnhookCodeEx

LM_VmtNew
LM_VmtHook
LM_VmtUnhook
LM_VmtGetOriginal
LM_VmtReset
LM_VmtFree
```

## Contributing
Read the file `CONTRIBUTING.md` in the root directory of this repository

## Projects
Made with libmem:  
- [AssaultCube Multihack](https://github.com/rdbo/AssaultCube-Multihack)  
- [X-Inject](https://github.com/rdbo/x-inject)  
- [DirectX9 BaseHook](https://github.com/rdbo/DX9-BaseHook)  
- [DirectX11 BaseHook](https://github.com/rdbo/DX11-BaseHook)  
- [OpenGL BaseHook](https://github.com/rdbo/GL-BaseHook)  
- [Counter-Strike 1.6 BaseHook](https://github.com/rdbo/cstrike-basehook)  
