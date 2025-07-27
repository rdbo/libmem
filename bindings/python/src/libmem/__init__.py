#  ----------------------------------
# |         libmem - by rdbo         |
# |      Memory Hacking Library      |
#  ----------------------------------
#
# Copyright (C) 2024    Rdbo
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License version 3
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import libmem._libmem as _libmem
from libmem._libmem import lm_process_t as Process, lm_thread_t as Thread, lm_module_t as Module, lm_symbol_t as Symbol, lm_prot_t as Prot, lm_segment_t as Segment, lm_inst_t as Inst, lm_vmt_t as Vmt, lm_arch_t as Arch
from libmem._libmem import LM_PROT_X as PROT_X, LM_PROT_R as PROT_R, LM_PROT_W as PROT_W, LM_PROT_XR as PROT_XR, LM_PROT_XW as PROT_XW, LM_PROT_RW as PROT_RW, LM_PROT_XRW as PROT_XRW, LM_ARCH_ARMV7 as ARCH_ARMV7, LM_ARCH_ARMV8 as ARCH_ARMV8, LM_ARCH_THUMBV7 as ARCH_THUMBV7, LM_ARCH_THUMBV8 as ARCH_THUMBV8, LM_ARCH_ARMV7EB as ARCH_ARMV7EB, LM_ARCH_THUMBV7EB as ARCH_THUMBV7EB, LM_ARCH_ARMV8EB as ARCH_ARMV8EB, LM_ARCH_THUMBV8EB as ARCH_THUMBV8EB, LM_ARCH_AARCH64 as ARCH_AARCH64, LM_ARCH_MIPS as ARCH_MIPS, LM_ARCH_MIPS64 as ARCH_MIPS64, LM_ARCH_MIPSEL as ARCH_MIPSEL, LM_ARCH_MIPSEL64 as ARCH_MIPSEL64, LM_ARCH_X86_16 as ARCH_X86_16, LM_ARCH_X86 as ARCH_X86, LM_ARCH_X64 as ARCH_X64, LM_ARCH_PPC32 as ARCH_PPC32, LM_ARCH_PPC64 as ARCH_PPC64, LM_ARCH_PPC64LE as ARCH_PPC64LE, LM_ARCH_SPARC as ARCH_SPARC, LM_ARCH_SPARC64 as ARCH_SPARC64, LM_ARCH_SPARCEL as ARCH_SPARCEL, LM_ARCH_SYSZ as ARCH_SYSZ, LM_ARCH_MAX as ARCH_MAX
from typing import Optional, List, Tuple

def enum_processes() -> Optional[List[Process]]:
    return _libmem.LM_EnumProcesses()
enum_processes.__doc__ = _libmem.LM_EnumProcesses.__doc__

def get_process() -> Optional[Process]:
    return _libmem.LM_GetProcess()
get_process.__doc__ = _libmem.LM_GetProcess.__doc__

def get_process_ex(pid: int) -> Optional[Process]:
    return _libmem.LM_GetProcessEx(pid)
get_process_ex.__doc__ = _libmem.LM_GetProcessEx.__doc__

def get_command_line(proc: Process) -> Optional[List[str]]:
    return _libmem.LM_GetCommandLine(proc)
get_command_line.__doc__ = _libmem.LM_GetCommandLine.__doc__

def find_process(process_name: str) -> Optional[Process]:
    return _libmem.LM_FindProcess(process_name)
find_process.__doc__ = _libmem.LM_FindProcess.__doc__

def is_process_alive(process: Process) -> bool:
    return _libmem.LM_IsProcessAlive(process)
is_process_alive.__doc__ = _libmem.LM_IsProcessAlive.__doc__

def get_bits() -> int:
    return _libmem.LM_GetBits()
get_bits.__doc__ = _libmem.LM_GetBits.__doc__

def get_system_bits() -> int:
    return _libmem.LM_GetSystemBits()
get_system_bits.__doc__ = _libmem.LM_GetSystemBits.__doc__

# --------------------------------

def enum_threads() -> Optional[List[Thread]]:
    return _libmem.LM_EnumThreads()
enum_threads.__doc__ = _libmem.LM_EnumThreads.__doc__

def enum_threads_ex(process: Process) -> Optional[List[Thread]]:
    return _libmem.LM_EnumThreadsEx(process)
enum_threads_ex.__doc__ = _libmem.LM_EnumThreadsEx.__doc__

def get_thread() -> Optional[Thread]:
    return _libmem.LM_GetThread()
get_thread.__doc__ = _libmem.LM_GetThread.__doc__

def get_thread_ex(process: Process) -> Optional[Thread]:
    return _libmem.LM_GetThreadEx(process)
get_thread_ex.__doc__ = _libmem.LM_GetThreadEx.__doc__

def get_thread_process(thread: Thread) -> Optional[Process]:
    return _libmem.LM_GetThreadProcess(thread)
get_thread_process.__doc__ = _libmem.LM_GetThreadProcess.__doc__

# --------------------------------

def enum_modules() -> Optional[List[Module]]:
    return _libmem.LM_EnumModules()
enum_modules.__doc__ = _libmem.LM_EnumModules.__doc__

def enum_modules_ex(process: Process) -> Optional[List[Module]]:
    return _libmem.LM_EnumModulesEx(process)
enum_modules_ex.__doc__ = _libmem.LM_EnumModulesEx.__doc__

def find_module(module_name: str) -> Optional[Module]:
    return _libmem.LM_FindModule(module_name)
find_module.__doc__ = _libmem.LM_FindModule.__doc__

def find_module_ex(process: Process, module_name: str) -> Optional[Module]:
    return _libmem.LM_FindModuleEx(process, module_name)
find_module_ex.__doc__ = _libmem.LM_FindModuleEx.__doc__

def load_module(module_path: str) -> Optional[Module]:
    return _libmem.LM_LoadModule(module_path)
load_module.__doc__ = _libmem.LM_LoadModule.__doc__

def load_module_ex(process: Process, module_path: str) -> Optional[Module]:
    return _libmem.LM_LoadModuleEx(process, module_path)
load_module_ex.__doc__ = _libmem.LM_LoadModuleEx.__doc__

def unload_module(module: Module) -> bool:
    return _libmem.LM_UnloadModule(module)
unload_module.__doc__ = _libmem.LM_UnloadModule.__doc__

def unload_module_ex(process: Process, module: Module) -> bool:
    return _libmem.LM_UnloadModuleEx(process, module)
unload_module_ex.__doc__ = _libmem.LM_UnloadModuleEx.__doc__

# --------------------------------

def enum_symbols(module: Module) -> Optional[List[Symbol]]:
    return _libmem.LM_EnumSymbols(module)
enum_symbols.__doc__ = _libmem.LM_EnumSymbols.__doc__

def find_symbol_address(module: Module, symbol_name: str) -> Optional[int]:
    return _libmem.LM_FindSymbolAddress(module, symbol_name)
find_symbol_address.__doc__ = _libmem.LM_FindSymbolAddress.__doc__

def demangle_symbol(mangled_symbol: str) -> Optional[str]:
    return _libmem.LM_DemangleSymbol(mangled_symbol)
demangle_symbol.__doc__ = _libmem.LM_DemangleSymbol.__doc__

def enum_symbols_demangled(module: Module) -> Optional[List[Symbol]]:
    return _libmem.LM_EnumSymbolsDemangled(module)
enum_symbols_demangled.__doc__ = _libmem.LM_EnumSymbolsDemangled.__doc__

def find_symbol_address_demangled(module: Module, demangled_symbol_name: str):
    return _libmem.LM_FindSymbolAddressDemangled(module, demangled_symbol_name)
find_symbol_address_demangled.__doc__ = _libmem.LM_FindSymbolAddressDemangled.__doc__

# --------------------------------

def enum_segments() -> Optional[List[Segment]]:
    return _libmem.LM_EnumSegments()
enum_segments.__doc__ = _libmem.LM_EnumSegments.__doc__

def enum_segments_ex(process: Process) -> Optional[List[Segment]]:
    return _libmem.LM_EnumSegmentsEx(process)
enum_segments_ex.__doc__ = _libmem.LM_EnumSegmentsEx.__doc__

def find_segment(address: int) -> Optional[Segment]:
    return _libmem.LM_FindSegment(address)
find_segment.__doc__ = _libmem.LM_FindSegment.__doc__

def find_segment_ex(process: Process, address: int) -> Optional[Segment]:
    return _libmem.LM_FindSegmentEx(process, address)
find_segment_ex.__doc__ = _libmem.LM_FindSegmentEx.__doc__

# --------------------------------

def read_memory(src: int, size: int) -> Optional[bytearray]:
    return _libmem.LM_ReadMemory(src, size)
read_memory.__doc__ = _libmem.LM_ReadMemory.__doc__

def read_memory_ex(process: Process, source: int, size: int) -> Optional[bytearray]:
    return _libmem.LM_ReadMemoryEx(process, source, size)
read_memory_ex.__doc__ = _libmem.LM_ReadMemoryEx.__doc__

def write_memory(dest: int, source: bytearray) -> bool:
    return _libmem.LM_WriteMemory(dest, source)
write_memory.__doc__ = _libmem.LM_WriteMemory.__doc__

def write_memory_ex(process: Process, dest: int, source: bytearray) -> bool:
    return _libmem.LM_WriteMemoryEx(process, dest, source)
write_memory_ex.__doc__ = _libmem.LM_WriteMemoryEx.__doc__

def set_memory(dest: int, byte: bytes, size: int) -> bool:
    return _libmem.LM_SetMemory(dest, byte, size)
set_memory.__doc__ = _libmem.LM_SetMemory.__doc__

def set_memory_ex(process: Process, dest: int, byte: bytes, size: int) -> bool:
    return _libmem.LM_SetMemoryEx(process, dest, byte, size)
set_memory_ex.__doc__ = _libmem.LM_SetMemoryEx.__doc__

def prot_memory(address: int, size: int, prot: Prot) -> Optional[Prot]:
    return _libmem.LM_ProtMemory(address, size, prot)
prot_memory.__doc__ = _libmem.LM_ProtMemory.__doc__

def prot_memory_ex(process: Process, address: int, size: int, prot: Prot) -> Optional[Prot]:
    return _libmem.LM_ProtMemoryEx(process, address, size, prot)
prot_memory_ex.__doc__ = _libmem.LM_ProtMemoryEx.__doc__

def alloc_memory(size: int, prot: Prot) -> Optional[int]:
    return _libmem.LM_AllocMemory(size, prot)
alloc_memory.__doc__ = _libmem.LM_AllocMemory.__doc__

def alloc_memory_ex(process: Process, size: int, prot: Prot) -> Optional[int]:
    return _libmem.LM_AllocMemoryEx(process, size, prot)
alloc_memory_ex.__doc__ = _libmem.LM_AllocMemoryEx.__doc__

def free_memory(address: int, size: int) -> bool:
    return _libmem.LM_FreeMemory(address, size)
free_memory.__doc__ = _libmem.LM_FreeMemory.__doc__

def free_memory_ex(process: Process, address: int, size: int) -> bool:
    return _libmem.LM_FreeMemoryEx(process, address, size)
free_memory_ex.__doc__ = _libmem.LM_FreeMemoryEx.__doc__

def deep_pointer(base: int, offsets: List[int]) -> Optional[int]:
    return _libmem.LM_DeepPointer(base, offsets)
deep_pointer.__doc__ = _libmem.LM_DeepPointer.__doc__

def deep_pointer_ex(process: Process, base: int, offsets: List[int]) -> Optional[int]:
    return _libmem.LM_DeepPointerEx(process, base, offsets)
deep_pointer_ex.__doc__ = _libmem.LM_DeepPointerEx.__doc__

# --------------------------------

def data_scan(data: bytearray, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_DataScan(data, address, scansize)
data_scan.__doc__ = _libmem.LM_DataScan.__doc__

def data_scan_ex(process: Process, data: bytearray, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_DataScanEx(process, data, address, scansize)
data_scan_ex.__doc__ = _libmem.LM_DataScanEx.__doc__

def pattern_scan(pattern: bytearray, mask: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_PatternScan(pattern, mask, address, scansize)
pattern_scan.__doc__ = _libmem.LM_PatternScan.__doc__

def pattern_scan_ex(process: Process, pattern: bytearray, mask: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_PatternScanEx(process, pattern, mask, address, scansize)
pattern_scan_ex.__doc__ = _libmem.LM_PatternScanEx.__doc__

def sig_scan(signature: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_SigScan(signature, address, scansize)
sig_scan.__doc__ = _libmem.LM_SigScan.__doc__

def sig_scan_ex(process: Process, signature: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_SigScanEx(process, signature, address, scansize)
sig_scan_ex.__doc__ = _libmem.LM_SigScanEx.__doc__

# --------------------------------

def hook_code(from_address: int, to_address: int) -> Optional[Tuple[int, int]]:
    return _libmem.LM_HookCode(from_address, to_address)
hook_code.__doc__ = _libmem.LM_HookCode.__doc__

def hook_code_ex(process: Process, from_address: int, to_address: int) -> Optional[Tuple[int, int]]:
    return _libmem.LM_HookCodeEx(process, from_address, to_address)
hook_code_ex.__doc__ = _libmem.LM_HookCodeEx.__doc__

def unhook_code(from_address: int, trampoline: Tuple[int, int]) -> bool:
    return _libmem.LM_UnhookCode(from_address, trampoline)
unhook_code.__doc__ = _libmem.LM_UnhookCode.__doc__

def unhook_code_ex(process: Process, from_address: int, trampoline: Tuple[int, int]) -> bool:
    return _libmem.LM_UnhookCodeEx(process, from_address, trampoline)
unhook_code_ex.__doc__ = _libmem.LM_UnhookCodeEx.__doc__

# --------------------------------

def get_architecture() -> Arch:
    return _libmem.LM_GetArchitecture()
get_architecture.__doc__ = _libmem.LM_GetArchitecture.__doc__

def assemble(code: str) -> Optional[Inst]:
    return _libmem.LM_Assemble(code)
assemble.__doc__ = _libmem.LM_Assemble.__doc__

def assemble_ex(code: str, arch: Arch, runtime_address: int) -> Optional[bytearray]:
    return _libmem.LM_AssembleEx(code, arch, runtime_address)
assemble_ex.__doc__ = _libmem.LM_AssembleEx.__doc__

def disassemble(machine_code: int) -> Optional[Inst]:
    return _libmem.LM_Disassemble(machine_code)
disassemble.__doc__ = _libmem.LM_Disassemble.__doc__

def disassemble_ex(machine_code: int, arch: Arch, max_size: int, instructions_count: int, runtime_address: int) -> Optional[List[Inst]]:
    return _libmem.LM_DisassembleEx(machine_code, arch, max_size, instructions_count, runtime_address)
disassemble_ex.__doc__ = _libmem.LM_DisassembleEx.__doc__

def code_length(machine_code: int, min_length: int) -> Optional[int]:
    return _libmem.LM_CodeLength(machine_code, min_length)
code_length.__doc__ = _libmem.LM_CodeLength.__doc__

def code_length_ex(process: Process, machine_code: int, min_length: int) -> Optional[int]:
    return _libmem.LM_CodeLengthEx(process, machine_code, min_length)
code_length_ex.__doc__ = _libmem.LM_CodeLengthEx.__doc__

