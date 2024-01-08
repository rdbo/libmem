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
from libmem._libmem import lm_process_t, lm_thread_t, lm_module_t, lm_symbol_t, lm_prot_t, lm_page_t, lm_inst_t, lm_vmt_t
from typing import Optional, List, Tuple

def LM_FreeMemory(alloc : int, size : int):
    return _libmem.LM_FreeMemory(alloc , size )

def LM_Assemble(code: str) -> Optional[lm_inst_t]:
    return _libmem.LM_Assemble(code)

def LM_DemangleSymbol(symbol: str) -> Optional[str]:
    return _libmem.LM_DemangleSymbol(symbol)

def LM_EnumPagesEx(pproc: lm_process_t) -> Optional[List[lm_page_t]]:
    return _libmem.LM_EnumPagesEx(pproc)

def LM_EnumSymbolsDemangled(pmod : lm_module_t):
    return _libmem.LM_EnumSymbolsDemangled(pmod )

def LM_ProtMemory(addr : int, size : int, prot : lm_prot_t):
    return _libmem.LM_ProtMemory(addr , size , prot )

def LM_IsProcessAlive(pproc : lm_process_t):
    return _libmem.LM_IsProcessAlive(pproc )

def LM_SetMemory(dst : int, byte : bytes, size : int):
    return _libmem.LM_SetMemory(dst , byte , size )

def LM_AllocMemory(size: int, prot: int) -> Optional[int]:
    return _libmem.LM_AllocMemory(size, prot)

def LM_DataScan(data: bytearray, addr: int, scansize: int) -> Optional[int]:
    return _libmem.LM_DataScan(data, addr, scansize)

def LM_UnhookCode(from_: int, trampoline: Tuple[int, int]) -> None:
    return _libmem.LM_UnhookCode(from_, trampoline, int)

def LM_SetMemoryEx(pproc : lm_process_t, dst : int, byte : bytes, size : int):
    return _libmem.LM_SetMemoryEx(pproc , dst , byte , size )

def LM_EnumThreads():
    return _libmem.LM_EnumThreads()

def LM_SigScanEx(pproc : lm_process_t, sig : str, addr : int, scansize : int):
    return _libmem.LM_SigScanEx(pproc , sig , addr , scansize )

def LM_GetThreadProcess(pthr: lm_thread_t) -> Optional[lm_process_t]:
    return _libmem.LM_GetThreadProcess(pthr)

def LM_EnumPages():
    return _libmem.LM_EnumPages()

def LM_ReadMemoryEx(pproc : lm_process_t, src : int, size : int):
    return _libmem.LM_ReadMemoryEx(pproc , src , size )

def LM_EnumModulesEx(pproc : lm_process_t):
    return _libmem.LM_EnumModulesEx(pproc )

def LM_HookCodeEx(pproc: lm_process_t, from_: int, to: int) -> Tuple[int, int]:
    return _libmem.LM_HookCodeEx(pproc, from_, to)

def LM_CodeLength(code: int, minlength: int) -> Optional[int]:
    return _libmem.LM_CodeLength(code, minlength)

def LM_FreeMemoryEx(pproc : lm_process_t, alloc : int, size : int):
    return _libmem.LM_FreeMemoryEx(pproc , alloc , size )

def LM_DisassembleEx(code: int, bits: int, size: int, count: int, runtime_addr: int) -> Optional[List[lm_inst_t]]:
    return _libmem.LM_DisassembleEx(code, bits, size, count, runtime_addr)

def LM_CodeLengthEx(pproc: lm_process_t, code: int, minlength: int) -> Optional[int]:
    return _libmem.LM_CodeLengthEx(pproc, code, minlength)

def LM_Disassemble(code: int) -> Optional[lm_inst_t]:
    return _libmem.LM_Disassemble(code)

def LM_GetPageEx(pproc : lm_process_t, addr : int):
    return _libmem.LM_GetPageEx(pproc , addr )

def LM_GetProcess():
    return _libmem.LM_GetProcess()

def LM_UnloadModule(pmod : lm_module_t):
    return _libmem.LM_UnloadModule(pmod )

def LM_WriteMemory(dst : int, src : bytearray):
    return _libmem.LM_WriteMemory(dst , src )

def LM_EnumThreadsEx(pproc : lm_process_t):
    return _libmem.LM_EnumThreadsEx(pproc )

def LM_GetThread():
    return _libmem.LM_GetThread()

def LM_LoadModuleEx(pproc : lm_process_t, modpath : str):
    return _libmem.LM_LoadModuleEx(pproc , modpath )

def LM_DataScanEx(pproc: lm_process_t, data: bytearray, addr: int, scansize: int) -> Optional[int]:
    return _libmem.LM_DataScanEx(pproc, data, addr, scansize)

def LM_HookCode(from_: int, to: int) -> Tuple[int, int]:
    return _libmem.LM_HookCode(from_, to)

def LM_GetSystemBits() -> int:
    return _libmem.LM_GetSystemBits()

def LM_LoadModule(modpath : str):
    return _libmem.LM_LoadModule(modpath )

def LM_FindModuleEx(pproc: lm_process_t, name: str) -> Optional[lm_module_t]:
    return _libmem.LM_FindModuleEx(pproc, name)

def LM_ProtMemoryEx(pproc : lm_process_t, addr : int, size : int, prot : lm_prot_t):
    return _libmem.LM_ProtMemoryEx(pproc , addr , size , prot )

def LM_GetProcessEx(pid : int):
    return _libmem.LM_GetProcessEx(pid )

def LM_GetPage(addr : int):
    return _libmem.LM_GetPage(addr )

def LM_FindModule(name : str):
    return _libmem.LM_FindModule(name )

def LM_PatternScanEx(pproc : lm_process_t, pattern : bytearray, mask : str, addr : int, scansize : int):
    return _libmem.LM_PatternScanEx(pproc , pattern , mask , addr , scansize )

def LM_UnloadModuleEx(pproc : lm_process_t, pmod : lm_module_t):
    return _libmem.LM_UnloadModuleEx(pproc , pmod )

def LM_PatternScan(pattern : bytearray, mask : str, addr : int, scansize : int):
    return _libmem.LM_PatternScan(pattern , mask , addr , scansize )

def LM_FindProcess(procstr : str):
    return _libmem.LM_FindProcess(procstr )

def LM_EnumModules() -> Optional[List[lm_module_t]]:
    return _libmem.LM_EnumModules()

def LM_FindSymbolAddress(pmod : lm_module_t, name : str):
    return _libmem.LM_FindSymbolAddress(pmod , name )

def LM_AssembleEx(code: str, bits: int, runtime_addr: int) -> Optional[bytearray]:
    return _libmem.LM_AssembleEx(code, bits, runtime_addr)

def LM_ReadMemory(src : int, size : int):
    return _libmem.LM_ReadMemory(src , size )

def LM_EnumProcesses():
    return _libmem.LM_EnumProcesses()

def LM_GetThreadEx(pproc : lm_process_t):
    return _libmem.LM_GetThreadEx(pproc )

def LM_FindSymbolAddressDemangled(pmod : lm_module_t, name : str):
    return _libmem.LM_FindSymbolAddressDemangled(pmod , name )

def LM_WriteMemoryEx(pproc : lm_process_t, dst : int, src : bytearray):
    return _libmem.LM_WriteMemoryEx(pproc , dst , src )

def LM_SigScan(sig : str, addr : int, scansize : int):
    return _libmem.LM_SigScan(sig , addr , scansize )

def LM_EnumSymbols(pmod : lm_module_t):
    return _libmem.LM_EnumSymbols(pmod )

def LM_UnhookCodeEx(pproc: lm_process_t, from_: int, trampoline: Tuple[int, int]) -> None:
    return _libmem.LM_UnhookCodeEx(pproc, from_, trampoline, int)

def LM_AllocMemoryEx(pproc: lm_process_t, size: int, prot: int) -> Optional[int]:
    return _libmem.LM_AllocMemoryEx(pproc, size, prot)
