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
from libmem._libmem import lm_process_t, lm_thread_t, lm_module_t, lm_symbol_t, lm_prot_t, lm_segment_t, lm_inst_t, lm_vmt_t, lm_arch_t
from libmem._libmem import LM_PROT_X, LM_PROT_R, LM_PROT_W, LM_PROT_XR, LM_PROT_XW, LM_PROT_RW, LM_PROT_XRW, LM_ARCH_ARMV7, LM_ARCH_ARMV8, LM_ARCH_THUMBV7, LM_ARCH_THUMBV8, LM_ARCH_ARMV7EB, LM_ARCH_THUMBV7EB, LM_ARCH_ARMV8EB, LM_ARCH_THUMBV8EB, LM_ARCH_AARCH64, LM_ARCH_MIPS, LM_ARCH_MIPS64, LM_ARCH_MIPSEL, LM_ARCH_MIPSEL64, LM_ARCH_X86_16, LM_ARCH_X86, LM_ARCH_X64, LM_ARCH_PPC32, LM_ARCH_PPC64, LM_ARCH_PPC64LE, LM_ARCH_SPARC, LM_ARCH_SPARC64, LM_ARCH_SPARCEL, LM_ARCH_SYSZ, LM_ARCH_MAX
from typing import Optional, List, Tuple

def LM_EnumProcesses() -> Optional[List[lm_process_t]]:
    return _libmem.LM_EnumProcesses()
LM_EnumProcesses.__doc__ = _libmem.LM_EnumProcesses.__doc__

def LM_GetProcess() -> Optional[lm_process_t]:
    return _libmem.LM_GetProcess()
LM_GetProcess.__doc__ = _libmem.LM_GetProcess.__doc__

def LM_GetProcessEx(pid: int) -> Optional[lm_process_t]:
    return _libmem.LM_GetProcessEx(pid)
LM_GetProcessEx.__doc__ = _libmem.LM_GetProcessEx.__doc__

def LM_FindProcess(process_name: str) -> Optional[lm_process_t]:
    return _libmem.LM_FindProcess(process_name)
LM_FindProcess.__doc__ = _libmem.LM_FindProcess.__doc__

def LM_IsProcessAlive(process: lm_process_t) -> bool:
    return _libmem.LM_IsProcessAlive(process)
LM_IsProcessAlive.__doc__ = _libmem.LM_IsProcessAlive.__doc__

def LM_GetBits() -> int:
    return _libmem.LM_GetBits()
LM_GetBits.__doc__ = _libmem.LM_GetBits.__doc__

def LM_GetSystemBits() -> int:
    return _libmem.LM_GetSystemBits()
LM_GetSystemBits.__doc__ = _libmem.LM_GetSystemBits.__doc__

# --------------------------------

def LM_EnumThreads() -> Optional[List[lm_thread_t]]:
    return _libmem.LM_EnumThreads()
LM_EnumThreads.__doc__ = _libmem.LM_EnumThreads.__doc__

def LM_EnumThreadsEx(process: lm_process_t) -> Optional[List[lm_thread_t]]:
    return _libmem.LM_EnumThreadsEx(process)
LM_EnumThreadsEx.__doc__ = _libmem.LM_EnumThreadsEx.__doc__

def LM_GetThread() -> Optional[lm_thread_t]:
    return _libmem.LM_GetThread()
LM_GetThread.__doc__ = _libmem.LM_GetThread.__doc__

def LM_GetThreadEx(process: lm_process_t) -> Optional[lm_thread_t]:
    return _libmem.LM_GetThreadEx(process)
LM_GetThreadEx.__doc__ = _libmem.LM_GetThreadEx.__doc__

def LM_GetThreadProcess(thread: lm_thread_t) -> Optional[lm_process_t]:
    return _libmem.LM_GetThreadProcess(thread)
LM_GetThreadProcess.__doc__ = _libmem.LM_GetThreadProcess.__doc__

# --------------------------------

def LM_EnumModules() -> Optional[List[lm_module_t]]:
    return _libmem.LM_EnumModules()
LM_EnumModules.__doc__ = _libmem.LM_EnumModules.__doc__

def LM_EnumModulesEx(process: lm_process_t) -> Optional[List[lm_module_t]]:
    return _libmem.LM_EnumModulesEx(process)
LM_EnumModulesEx.__doc__ = _libmem.LM_EnumModulesEx.__doc__

def LM_FindModule(module_name: str) -> Optional[lm_module_t]:
    return _libmem.LM_FindModule(module_name)
LM_FindModule.__doc__ = _libmem.LM_FindModule.__doc__

def LM_FindModuleEx(process: lm_process_t, module_name: str) -> Optional[lm_module_t]:
    return _libmem.LM_FindModuleEx(process, module_name)
LM_FindModuleEx.__doc__ = _libmem.LM_FindModuleEx.__doc__

def LM_LoadModule(module_path: str) -> Optional[lm_module_t]:
    return _libmem.LM_LoadModule(module_path)
LM_LoadModule.__doc__ = _libmem.LM_LoadModule.__doc__

def LM_LoadModuleEx(process: lm_process_t, module_path: str) -> Optional[lm_module_t]:
    return _libmem.LM_LoadModuleEx(process, module_path)
LM_LoadModuleEx.__doc__ = _libmem.LM_LoadModuleEx.__doc__

def LM_UnloadModule(module: lm_module_t) -> bool:
    return _libmem.LM_UnloadModule(module)
LM_UnloadModule.__doc__ = _libmem.LM_UnloadModule.__doc__

def LM_UnloadModuleEx(process: lm_process_t, module: lm_module_t) -> bool:
    return _libmem.LM_UnloadModuleEx(process, module)
LM_UnloadModuleEx.__doc__ = _libmem.LM_UnloadModuleEx.__doc__

# --------------------------------

def LM_EnumSymbols(module: lm_module_t) -> Optional[List[lm_symbol_t]]:
    return _libmem.LM_EnumSymbols(module)
LM_EnumSymbols.__doc__ = _libmem.LM_EnumSymbols.__doc__

def LM_FindSymbolAddress(module: lm_module_t, symbol_name: str) -> Optional[int]:
    return _libmem.LM_FindSymbolAddress(module, symbol_name)
LM_FindSymbolAddress.__doc__ = _libmem.LM_FindSymbolAddress.__doc__

def LM_DemangleSymbol(mangled_symbol: str) -> Optional[str]:
    return _libmem.LM_DemangleSymbol(mangled_symbol)
LM_DemangleSymbol.__doc__ = _libmem.LM_DemangleSymbol.__doc__

def LM_EnumSymbolsDemangled(module: lm_module_t) -> Optional[List[lm_symbol_t]]:
    return _libmem.LM_EnumSymbolsDemangled(module)
LM_EnumSymbolsDemangled.__doc__ = _libmem.LM_EnumSymbolsDemangled.__doc__

def LM_FindSymbolAddressDemangled(module: lm_module_t, demangled_symbol_name: str):
    return _libmem.LM_FindSymbolAddressDemangled(module, demangled_symbol_name)
LM_FindSymbolAddressDemangled.__doc__ = _libmem.LM_FindSymbolAddressDemangled.__doc__

# --------------------------------

def LM_EnumSegments() -> Optional[List[lm_segment_t]]:
    return _libmem.LM_EnumSegments()
LM_EnumSegments.__doc__ = _libmem.LM_EnumSegments.__doc__

def LM_EnumSegmentsEx(process: lm_process_t) -> Optional[List[lm_segment_t]]:
    return _libmem.LM_EnumSegmentsEx(process)
LM_EnumSegmentsEx.__doc__ = _libmem.LM_EnumSegmentsEx.__doc__

def LM_FindSegment(address: int) -> Optional[lm_segment_t]:
    return _libmem.LM_FindSegment(address)
LM_FindSegment.__doc__ = _libmem.LM_FindSegment.__doc__

def LM_FindSegmentEx(process: lm_process_t, address: int) -> Optional[lm_segment_t]:
    return _libmem.LM_FindSegmentEx(process, address)
LM_FindSegmentEx.__doc__ = _libmem.LM_FindSegmentEx.__doc__

# --------------------------------

def LM_ReadMemory(src: int, size: int) -> Optional[bytearray]:
    return _libmem.LM_ReadMemory(src, size)
LM_ReadMemory.__doc__ = _libmem.LM_ReadMemory.__doc__

def LM_ReadMemoryEx(process: lm_process_t, source: int, size: int) -> Optional[bytearray]:
    return _libmem.LM_ReadMemoryEx(process, src, size)
LM_ReadMemoryEx.__doc__ = _libmem.LM_ReadMemoryEx.__doc__

def LM_WriteMemory(dest: int, source: bytearray) -> bool:
    return _libmem.LM_WriteMemory
LM_WriteMemory.__doc__ = _libmem.LM_WriteMemory.__doc__

def LM_WriteMemoryEx(process: lm_process_t, dest: int, source: bytearray) -> bool:
    return _libmem.LM_WriteMemoryEx(process, dest, source)
LM_WriteMemoryEx.__doc__ = _libmem.LM_WriteMemoryEx.__doc__

def LM_SetMemory(dest: int, byte: bytes, size: int) -> bool:
    return _libmem.LM_SetMemory(dest, byte, size)
LM_SetMemory.__doc__ = _libmem.LM_SetMemory.__doc__

def LM_SetMemoryEx(process: lm_process_t, dest: int, byte: bytes, size: int) -> bool:
    return _libmem.LM_SetMemoryEx(process, dest, byte, size)
LM_SetMemoryEx.__doc__ = _libmem.LM_SetMemoryEx.__doc__

def LM_ProtMemory(address: int, size: int, prot: lm_prot_t) -> Optional[lm_prot_t]:
    return _libmem.LM_ProtMemory(address, size, prot)
LM_ProtMemory.__doc__ = _libmem.LM_ProtMemory.__doc__

def LM_ProtMemoryEx(process: lm_process_t, address: int, size: int, prot: lm_prot_t) -> Optional[lm_prot_t]:
    return _libmem.LM_ProtMemoryEx(process, address, size, prot)
LM_ProtMemoryEx.__doc__ = _libmem.LM_ProtMemoryEx.__doc__

def LM_AllocMemory(size: int, prot: lm_prot_t) -> Optional[int]:
    return _libmem.LM_AllocMemory(size, prot)
LM_AllocMemory.__doc__ = _libmem.LM_AllocMemory.__doc__

def LM_AllocMemoryEx(process: lm_process_t, size: int, prot: lm_prot_t) -> Optional[int]:
    return _libmem.LM_AllocMemoryEx(process, size, prot)
LM_AllocMemoryEx.__doc__ = _libmem.LM_AllocMemoryEx.__doc__

def LM_FreeMemory(address: int, size: int) -> bool:
    return _libmem.LM_FreeMemory(address, size)
LM_FreeMemory.__doc__ = _libmem.LM_FreeMemory.__doc__

def LM_FreeMemoryEx(process: lm_process_t, address: int, size: int) -> bool:
    return _libmem.LM_FreeMemoryEx(process, address, size)
LM_FreeMemoryEx.__doc__ = _libmem.LM_FreeMemoryEx.__doc__

def LM_DeepPointer(base: int, offsets: List[int]) -> Optional[int]:
    return _libmem.LM_DeepPointer(base, offsets)
LM_DeepPointer.__doc__ = _libmem.LM_DeepPointer.__doc__

def LM_DeepPointerEx(process: lm_process_t, base: int, offsets: List[int]) -> Optional[int]:
    return _libmem.LM_DeepPointerEx(process, base, offsets)
LM_DeepPointerEx.__doc__ = _libmem.LM_DeepPointerEx.__doc__

# --------------------------------

def LM_DataScan(data: bytearray, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_DataScan(data, address, scansize)
LM_DataScan.__doc__ = _libmem.LM_DataScan.__doc__

def LM_DataScanEx(process: lm_process_t, data: bytearray, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_DataScanEx(process, data, address, scansize)
LM_DataScanEx.__doc__ = _libmem.LM_DataScanEx.__doc__

def LM_PatternScan(pattern: bytearray, mask: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_PatternScan(pattern, mask, address, scansize)
LM_PatternScan.__doc__ = _libmem.LM_PatternScan.__doc__

def LM_PatternScanEx(process: lm_process_t, pattern: bytearray, mask: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_PatternScanEx(process, pattern, mask, address, scansize)
LM_PatternScanEx.__doc__ = _libmem.LM_PatternScanEx.__doc__

def LM_SigScan(signature: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_SigScan(signature, address, scansize)
LM_SigScan.__doc__ = _libmem.LM_SigScan.__doc__

def LM_SigScanEx(process: lm_process_t, signature: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_SigScanEx(process, signature, address, scansize)
LM_SigScanEx.__doc__ = _libmem.LM_SigScanEx.__doc__

# --------------------------------

def LM_HookCode(from_address: int, to_address: int) -> Optional[Tuple[int, int]]:
    return _libmem.LM_HookCode(from_address, to_address)
LM_HookCode.__doc__ = _libmem.LM_HookCode.__doc__

def LM_HookCodeEx(process: lm_process_t, from_address: int, to_address: int) -> Optional[Tuple[int, int]]:
    return _libmem.LM_HookCodeEx(process, from_address, to_address)
LM_HookCodeEx.__doc__ = _libmem.LM_HookCodeEx.__doc__

def LM_UnhookCode(from_address: int, trampoline: Tuple[int, int]) -> bool:
    return _libmem.LM_UnhookCode(from_address, trampoline)
LM_UnhookCode.__doc__ = _libmem.LM_UnhookCode.__doc__

def LM_UnhookCodeEx(process: lm_process_t, from_address: int, trampoline: Tuple[int, int]) -> bool:
    return _libmem.LM_UnhookCodeEx(process, from_address, trampoline)
LM_UnhookCodeEx.__doc__ = _libmem.LM_UnhookCodeEx.__doc__

# --------------------------------

def LM_GetArchitecture() -> lm_arch_t:
    return _libmem.LM_GetArchitecture()
LM_GetArchitecture.__doc__ = _libmem.LM_GetArchitecture.__doc__

def LM_Assemble(code: str) -> Optional[lm_inst_t]:
    return _libmem.LM_Assemble(code)
LM_Assemble.__doc__ = _libmem.LM_Assemble.__doc__

def LM_AssembleEx(code: str, arch: lm_arch_t, runtime_address: int) -> Optional[bytearray]:
    return _libmem.LM_AssembleEx(code, arch, runtime_address)
LM_AssembleEx.__doc__ = _libmem.LM_AssembleEx.__doc__

def LM_Disassemble(machine_code: int) -> Optional[lm_inst_t]:
    return _libmem.LM_Disassemble(machine_code)
LM_Disassemble.__doc__ = _libmem.LM_Disassemble.__doc__

def LM_DisassembleEx(machine_code: int, arch: lm_arch_t, max_size: int, instructions_count: int, runtime_address: int) -> Optional[List[lm_inst_t]]:
    return _libmem.LM_DisassembleEx(machine_code, arch, max_size, instructions_count, runtime_address)
LM_DisassembleEx.__doc__ = _libmem.LM_DisassembleEx.__doc__

def LM_CodeLength(machine_code: int, min_length: int) -> Optional[int]:
    return _libmem.LM_CodeLength(machine_code, min_length)
LM_CodeLength.__doc__ = _libmem.LM_CodeLength.__doc__

def LM_CodeLengthEx(process: lm_process_t, machine_code: int, min_length: int) -> Optional[int]:
    return _libmem.LM_CodeLengthEx(process, machine_code, min_length)
LM_CodeLengthEx.__doc__ = _libmem.LM_CodeLengthEx.__doc__

