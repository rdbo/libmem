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

def EnumProcesses() -> Optional[List[Process]]:
    return _libmem.LM_EnumProcesses()
EnumProcesses.__doc__ = _libmem.LM_EnumProcesses.__doc__

def GetProcess() -> Optional[Process]:
    return _libmem.LM_GetProcess()
GetProcess.__doc__ = _libmem.LM_GetProcess.__doc__

def GetProcessEx(pid: int) -> Optional[Process]:
    return _libmem.LM_GetProcessEx(pid)
GetProcessEx.__doc__ = _libmem.LM_GetProcessEx.__doc__

def FindProcess(process_name: str) -> Optional[Process]:
    return _libmem.LM_FindProcess(process_name)
FindProcess.__doc__ = _libmem.LM_FindProcess.__doc__

def IsProcessAlive(process: Process) -> bool:
    return _libmem.LM_IsProcessAlive(process)
IsProcessAlive.__doc__ = _libmem.LM_IsProcessAlive.__doc__

def GetBits() -> int:
    return _libmem.LM_GetBits()
GetBits.__doc__ = _libmem.LM_GetBits.__doc__

def GetSystemBits() -> int:
    return _libmem.LM_GetSystemBits()
GetSystemBits.__doc__ = _libmem.LM_GetSystemBits.__doc__

# --------------------------------

def EnumThreads() -> Optional[List[Thread]]:
    return _libmem.LM_EnumThreads()
EnumThreads.__doc__ = _libmem.LM_EnumThreads.__doc__

def EnumThreadsEx(process: Process) -> Optional[List[Thread]]:
    return _libmem.LM_EnumThreadsEx(process)
EnumThreadsEx.__doc__ = _libmem.LM_EnumThreadsEx.__doc__

def GetThread() -> Optional[Thread]:
    return _libmem.LM_GetThread()
GetThread.__doc__ = _libmem.LM_GetThread.__doc__

def GetThreadEx(process: Process) -> Optional[Thread]:
    return _libmem.LM_GetThreadEx(process)
GetThreadEx.__doc__ = _libmem.LM_GetThreadEx.__doc__

def GetThreadProcess(thread: Thread) -> Optional[Process]:
    return _libmem.LM_GetThreadProcess(thread)
GetThreadProcess.__doc__ = _libmem.LM_GetThreadProcess.__doc__

# --------------------------------

def EnumModules() -> Optional[List[Module]]:
    return _libmem.LM_EnumModules()
EnumModules.__doc__ = _libmem.LM_EnumModules.__doc__

def EnumModulesEx(process: Process) -> Optional[List[Module]]:
    return _libmem.LM_EnumModulesEx(process)
EnumModulesEx.__doc__ = _libmem.LM_EnumModulesEx.__doc__

def FindModule(module_name: str) -> Optional[Module]:
    return _libmem.LM_FindModule(module_name)
FindModule.__doc__ = _libmem.LM_FindModule.__doc__

def FindModuleEx(process: Process, module_name: str) -> Optional[Module]:
    return _libmem.LM_FindModuleEx(process, module_name)
FindModuleEx.__doc__ = _libmem.LM_FindModuleEx.__doc__

def LoadModule(module_path: str) -> Optional[Module]:
    return _libmem.LM_LoadModule(module_path)
LoadModule.__doc__ = _libmem.LM_LoadModule.__doc__

def LoadModuleEx(process: Process, module_path: str) -> Optional[Module]:
    return _libmem.LM_LoadModuleEx(process, module_path)
LoadModuleEx.__doc__ = _libmem.LM_LoadModuleEx.__doc__

def UnloadModule(module: Module) -> bool:
    return _libmem.LM_UnloadModule(module)
UnloadModule.__doc__ = _libmem.LM_UnloadModule.__doc__

def UnloadModuleEx(process: Process, module: Module) -> bool:
    return _libmem.LM_UnloadModuleEx(process, module)
UnloadModuleEx.__doc__ = _libmem.LM_UnloadModuleEx.__doc__

# --------------------------------

def EnumSymbols(module: Module) -> Optional[List[Symbol]]:
    return _libmem.LM_EnumSymbols(module)
EnumSymbols.__doc__ = _libmem.LM_EnumSymbols.__doc__

def FindSymbolAddress(module: Module, symbol_name: str) -> Optional[int]:
    return _libmem.LM_FindSymbolAddress(module, symbol_name)
FindSymbolAddress.__doc__ = _libmem.LM_FindSymbolAddress.__doc__

def DemangleSymbol(mangled_symbol: str) -> Optional[str]:
    return _libmem.LM_DemangleSymbol(mangled_symbol)
DemangleSymbol.__doc__ = _libmem.LM_DemangleSymbol.__doc__

def EnumSymbolsDemangled(module: Module) -> Optional[List[Symbol]]:
    return _libmem.LM_EnumSymbolsDemangled(module)
EnumSymbolsDemangled.__doc__ = _libmem.LM_EnumSymbolsDemangled.__doc__

def FindSymbolAddressDemangled(module: Module, demangled_symbol_name: str):
    return _libmem.LM_FindSymbolAddressDemangled(module, demangled_symbol_name)
FindSymbolAddressDemangled.__doc__ = _libmem.LM_FindSymbolAddressDemangled.__doc__

# --------------------------------

def EnumSegments() -> Optional[List[Segment]]:
    return _libmem.LM_EnumSegments()
EnumSegments.__doc__ = _libmem.LM_EnumSegments.__doc__

def EnumSegmentsEx(process: Process) -> Optional[List[Segment]]:
    return _libmem.LM_EnumSegmentsEx(process)
EnumSegmentsEx.__doc__ = _libmem.LM_EnumSegmentsEx.__doc__

def FindSegment(address: int) -> Optional[Segment]:
    return _libmem.LM_FindSegment(address)
FindSegment.__doc__ = _libmem.LM_FindSegment.__doc__

def FindSegmentEx(process: Process, address: int) -> Optional[Segment]:
    return _libmem.LM_FindSegmentEx(process, address)
FindSegmentEx.__doc__ = _libmem.LM_FindSegmentEx.__doc__

# --------------------------------

def ReadMemory(src: int, size: int) -> Optional[bytearray]:
    return _libmem.LM_ReadMemory(src, size)
ReadMemory.__doc__ = _libmem.LM_ReadMemory.__doc__

def ReadMemoryEx(process: Process, source: int, size: int) -> Optional[bytearray]:
    return _libmem.LM_ReadMemoryEx(process, src, size)
ReadMemoryEx.__doc__ = _libmem.LM_ReadMemoryEx.__doc__

def WriteMemory(dest: int, source: bytearray) -> bool:
    return _libmem.LM_WriteMemory
WriteMemory.__doc__ = _libmem.LM_WriteMemory.__doc__

def WriteMemoryEx(process: Process, dest: int, source: bytearray) -> bool:
    return _libmem.LM_WriteMemoryEx(process, dest, source)
WriteMemoryEx.__doc__ = _libmem.LM_WriteMemoryEx.__doc__

def SetMemory(dest: int, byte: bytes, size: int) -> bool:
    return _libmem.LM_SetMemory(dest, byte, size)
SetMemory.__doc__ = _libmem.LM_SetMemory.__doc__

def SetMemoryEx(process: Process, dest: int, byte: bytes, size: int) -> bool:
    return _libmem.LM_SetMemoryEx(process, dest, byte, size)
SetMemoryEx.__doc__ = _libmem.LM_SetMemoryEx.__doc__

def ProtMemory(address: int, size: int, prot: Prot) -> Optional[Prot]:
    return _libmem.LM_ProtMemory(address, size, prot)
ProtMemory.__doc__ = _libmem.LM_ProtMemory.__doc__

def ProtMemoryEx(process: Process, address: int, size: int, prot: Prot) -> Optional[Prot]:
    return _libmem.LM_ProtMemoryEx(process, address, size, prot)
ProtMemoryEx.__doc__ = _libmem.LM_ProtMemoryEx.__doc__

def AllocMemory(size: int, prot: Prot) -> Optional[int]:
    return _libmem.LM_AllocMemory(size, prot)
AllocMemory.__doc__ = _libmem.LM_AllocMemory.__doc__

def AllocMemoryEx(process: Process, size: int, prot: Prot) -> Optional[int]:
    return _libmem.LM_AllocMemoryEx(process, size, prot)
AllocMemoryEx.__doc__ = _libmem.LM_AllocMemoryEx.__doc__

def FreeMemory(address: int, size: int) -> bool:
    return _libmem.LM_FreeMemory(address, size)
FreeMemory.__doc__ = _libmem.LM_FreeMemory.__doc__

def FreeMemoryEx(process: Process, address: int, size: int) -> bool:
    return _libmem.LM_FreeMemoryEx(process, address, size)
FreeMemoryEx.__doc__ = _libmem.LM_FreeMemoryEx.__doc__

def DeepPointer(base: int, offsets: List[int]) -> Optional[int]:
    return _libmem.LM_DeepPointer(base, offsets)
DeepPointer.__doc__ = _libmem.LM_DeepPointer.__doc__

def DeepPointerEx(process: Process, base: int, offsets: List[int]) -> Optional[int]:
    return _libmem.LM_DeepPointerEx(process, base, offsets)
DeepPointerEx.__doc__ = _libmem.LM_DeepPointerEx.__doc__

# --------------------------------

def DataScan(data: bytearray, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_DataScan(data, address, scansize)
DataScan.__doc__ = _libmem.LM_DataScan.__doc__

def DataScanEx(process: Process, data: bytearray, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_DataScanEx(process, data, address, scansize)
DataScanEx.__doc__ = _libmem.LM_DataScanEx.__doc__

def PatternScan(pattern: bytearray, mask: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_PatternScan(pattern, mask, address, scansize)
PatternScan.__doc__ = _libmem.LM_PatternScan.__doc__

def PatternScanEx(process: Process, pattern: bytearray, mask: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_PatternScanEx(process, pattern, mask, address, scansize)
PatternScanEx.__doc__ = _libmem.LM_PatternScanEx.__doc__

def SigScan(signature: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_SigScan(signature, address, scansize)
SigScan.__doc__ = _libmem.LM_SigScan.__doc__

def SigScanEx(process: Process, signature: str, address: int, scansize: int) -> Optional[int]:
    return _libmem.LM_SigScanEx(process, signature, address, scansize)
SigScanEx.__doc__ = _libmem.LM_SigScanEx.__doc__

# --------------------------------

def HookCode(from_address: int, to_address: int) -> Optional[Tuple[int, int]]:
    return _libmem.LM_HookCode(from_address, to_address)
HookCode.__doc__ = _libmem.LM_HookCode.__doc__

def HookCodeEx(process: Process, from_address: int, to_address: int) -> Optional[Tuple[int, int]]:
    return _libmem.LM_HookCodeEx(process, from_address, to_address)
HookCodeEx.__doc__ = _libmem.LM_HookCodeEx.__doc__

def UnhookCode(from_address: int, trampoline: Tuple[int, int]) -> bool:
    return _libmem.LM_UnhookCode(from_address, trampoline)
UnhookCode.__doc__ = _libmem.LM_UnhookCode.__doc__

def UnhookCodeEx(process: Process, from_address: int, trampoline: Tuple[int, int]) -> bool:
    return _libmem.LM_UnhookCodeEx(process, from_address, trampoline)
UnhookCodeEx.__doc__ = _libmem.LM_UnhookCodeEx.__doc__

# --------------------------------

def GetArchitecture() -> Arch:
    return _libmem.LM_GetArchitecture()
GetArchitecture.__doc__ = _libmem.LM_GetArchitecture.__doc__

def Assemble(code: str) -> Optional[Inst]:
    return _libmem.LM_Assemble(code)
Assemble.__doc__ = _libmem.LM_Assemble.__doc__

def AssembleEx(code: str, arch: Arch, runtime_address: int) -> Optional[bytearray]:
    return _libmem.LM_AssembleEx(code, arch, runtime_address)
AssembleEx.__doc__ = _libmem.LM_AssembleEx.__doc__

def Disassemble(machine_code: int) -> Optional[Inst]:
    return _libmem.LM_Disassemble(machine_code)
Disassemble.__doc__ = _libmem.LM_Disassemble.__doc__

def DisassembleEx(machine_code: int, arch: Arch, max_size: int, instructions_count: int, runtime_address: int) -> Optional[List[Inst]]:
    return _libmem.LM_DisassembleEx(machine_code, arch, max_size, instructions_count, runtime_address)
DisassembleEx.__doc__ = _libmem.LM_DisassembleEx.__doc__

def CodeLength(machine_code: int, min_length: int) -> Optional[int]:
    return _libmem.LM_CodeLength(machine_code, min_length)
CodeLength.__doc__ = _libmem.LM_CodeLength.__doc__

def CodeLengthEx(process: Process, machine_code: int, min_length: int) -> Optional[int]:
    return _libmem.LM_CodeLengthEx(process, machine_code, min_length)
CodeLengthEx.__doc__ = _libmem.LM_CodeLengthEx.__doc__

