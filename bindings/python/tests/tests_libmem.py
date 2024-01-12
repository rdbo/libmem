import unittest
from libmem import *


class TestLibMem(unittest.TestCase):

    def setUp(self):
        self.normal_program = LM_GetProcess()
        self.normal_program_module = LM_FindModule(self.normal_program.name)
        self.ex_program = LM_FindProcess("notepad.exe")
        self.ex_program_module = LM_FindModuleEx(self.ex_program, "notepad.exe")
        self.prot_flag = LM_PROT_XRW
        self.test_size = 1024
        self.test_module = "TestDLL.dll"
        self.test_pattern = bytearray([0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x72])
        self.test_mask = "xx?xx?x"

    def test_LM_AllocMemory(self):
        # def LM_AllocMemory(size: int, prot: int) -> Optional[int]:
        address = LM_AllocMemory(self.test_size, self.prot_flag)
        self.assertIsNotNone(address)

    def test_LM_AllocMemoryEx(self):
        # def LM_AllocMemoryEx(pproc: lm_process_t, size: int, prot: int) -> Optional[int]:
        address = LM_AllocMemoryEx(self.ex_program, self.test_size, self.prot_flag)
        self.assertIsNotNone(address)

    def test_LM_Assemble(self):
        # def LM_Assemble(code: str) -> Optional[lm_inst_t]:
        inst = LM_Assemble("nop")
        self.assertIsNotNone(inst)

    def test_LM_AssembleEx(self):
        # def LM_AssembleEx(code: str, bits: int, runtime_addr: int) -> Optional[bytearray]:
        inst = LM_AssembleEx("nop", 64, 0x1000)
        self.assertIsNotNone(inst)

    def test_LM_CodeLength(self):
        # def LM_CodeLength(code: int, minlength: int) -> Optional[int]:
        length = LM_CodeLength(self.normal_program_module.base, 8)
        self.assertIsNotNone(length)

    def test_LM_CodeLengthEx(self):
        # def LM_CodeLengthEx(pproc: lm_process_t, code: int, minlength: int) -> Optional[int]:
        length = LM_CodeLengthEx(self.ex_program, self.ex_program_module.base, 8)
        self.assertIsNotNone(length)

    # def test_LM_Datascan(self):
    #     # def LM_DataScan(data: bytearray, addr: int, scansize: int) -> Optional[int]:
    #     self.assertIsNotNone(LM_DataScan(self.test_pattern, self.normal_program_module.base, 0x1000))

    # def test_LM_DataScanEx(self):
    #     # def LM_DataScanEx(pproc: lm_process_t, data: bytearray, addr: int, scansize: int) -> Optional[int]:
    #     self.assertIsNotNone(LM_DataScanEx(self.ex_program, self.test_pattern, self.ex_program_module.base, 0x1000))

    def test_LM_DeepPointer(self):
        # def LM_DeepPointer(base: int, offsets: List[int]) -> Optional[int]:
        self.assertIsNotNone(LM_DeepPointer(self.normal_program_module.base, [0x0, 0x0]))

    def test_LM_DeepPointerEx(self):
        # def LM_DeepPointerEx(pproc: lm_process_t, base: int, offsets: List[int]) -> Optional[int]:
        self.assertIsNotNone(LM_DeepPointerEx(self.ex_program, self.ex_program_module.base, [0x0, 0x0]))

    def test_LM_DemangleSymbol(self):
        self.assertIsNotNone(LM_DemangleSymbol("?test@@YAXXZ"))

    def test_LM_Disassemble(self):
        # def LM_Disassemble(code: int) -> Optional[lm_inst_t]:
        self.assertIsNotNone(LM_Disassemble(self.normal_program_module.base))

    # def test_LM_DisassembleEx(self):
    #     # def LM_DisassembleEx(code: int, bits: int, size: int, count: int, runtime_addr: int) -> Optional[List[lm_inst_t]]:
    #     self.assertIsNotNone(LM_DisassembleEx(self.ex_program_module.base, self.ex_program.bits, 8, 1, 1))

    def test_LM_EnumModules(self):
        # def LM_EnumModules() -> Optional[List[lm_module_t]]:
        self.assertIsNotNone(LM_EnumModules())

    def test_LM_EnumModulesEx(self):
        # def LM_EnumModulesEx(pproc: lm_process_t) -> Optional[List[lm_module_t]]:
        self.assertIsNotNone(LM_EnumModulesEx(self.ex_program))

    def test_LM_EnumPages(self):
        # def LM_EnumPages() -> Optional[List[lm_page_t]]:
        self.assertIsNotNone(LM_EnumPages())

    def test_LM_EnumPagesEx(self):
        # def LM_EnumPagesEx(pproc: lm_process_t) -> Optional[List[lm_page_t]]:
        self.assertIsNotNone(LM_EnumPagesEx(self.ex_program))

    def test_LM_EnumProcesses(self):
        # def LM_EnumProcesses() -> Optional[List[lm_process_t]]:
        self.assertIsNotNone(LM_EnumProcesses())

    def test_LM_EnumSymbols(self):
        # def LM_EnumSymbols(pmod: lm_module_t) -> Optional[lm_symbol_t]:
        self.assertIsNotNone(LM_EnumSymbols(LM_FindModule(LM_GetProcess().name)))

    def test_LM_EnumSymbolsDemangled(self):
        # def LM_EnumSymbolsDemangled(pmod: lm_module_t) -> Optional[List[lm_symbol_t]]:
        self.assertIsNotNone(LM_EnumSymbolsDemangled(LM_FindModule(LM_GetProcess().name)))

    def test_LM_EnumThreads(self):
        # def LM_EnumThreads() -> Optional[List[lm_thread_t]]:
        self.assertIsNotNone(LM_EnumThreads())

    def test_LM_EnumThreadsEx(self):
        # def LM_EnumThreadsEx(pproc: lm_process_t) -> Optional[List[lm_thread_t]]:
        self.assertIsNotNone(LM_EnumThreadsEx(self.ex_program))

    def test_LM_FindModule(self):
        # def LM_FindModule(name: str) -> Optional[lm_module_t]:
        self.assertIsNotNone(LM_FindModule(LM_GetProcess().name))

    def test_LM_FindModuleEx(self):
        # def LM_FindModuleEx(pproc: lm_process_t, name: str) -> Optional[lm_module_t]:
        self.assertIsNotNone(LM_FindModuleEx(self.ex_program, "notepad.exe"))

    def test_LM_FindProcess(self):
        # def LM_FindProcess(procstr: str) -> Optional[lm_process_t]:
        self.assertIsNotNone(LM_FindProcess("notepad.exe"))

    def test_LM_FindSymbolAddress(self):
        # def LM_FindSymbolAddress(pmod: lm_module_t, name: str) -> Optional[int]:
        self.assertIsNotNone(LM_FindSymbolAddress(self.ex_program_module, "?test@@YAXXZ"))

    def test_LM_FindSymbolAddressDemangled(self):
        # def LM_FindSymbolAddressDemangled(pmod: lm_module_t, name: str) -> Optional[int]:
        self.assertIsNotNone(LM_FindSymbolAddressDemangled(self.ex_program_module, "?test@@YAXXZ"))

    def test_LM_FreeMemory(self):
        # def LM_FreeMemory(alloc: int, size: int) -> bool:
        self.assertTrue(LM_FreeMemory(LM_AllocMemory(self.test_size, self.prot_flag), self.test_size))

    def test_LM_FreeMemoryEx(self):
        # def LM_FreeMemoryEx(pproc: lm_process_t, alloc: int, size: int) -> bool:
        self.assertTrue(
            LM_FreeMemoryEx(self.ex_program, LM_AllocMemoryEx(self.ex_program, self.test_size, self.prot_flag),
                            self.test_size))

    def test_LM_GetPage(self):
        # def LM_GetPage(addr: int) -> Optional[lm_page_t]:
        self.assertIsNotNone(LM_GetPage(self.normal_program_module.base))

    def test_LM_GetPageEx(self):
        # def LM_GetPageEx(pproc: lm_process_t, addr: int) -> Optional[lm_page_t]:
        self.assertIsNotNone(LM_GetPageEx(self.ex_program, self.ex_program_module.base))

    def test_LM_GetProcess(self):
        # def LM_GetProcess() -> Optional[lm_process_t]:
        self.assertIsNotNone(LM_GetProcess())

    def test_LM_GetProcessEx(self):
        # def LM_GetProcessEx(pid: int) -> Optional[lm_process_t]:
        self.assertIsNotNone(LM_GetProcessEx(self.ex_program.pid))

    def test_LM_GetSystemBits(self):
        # def LM_GetSystemBits() -> int:
        self.assertIsNotNone(LM_GetSystemBits())

    def test_LM_GetThread(self):
        # def LM_GetThread() -> Optional[lm_thread_t]:
        self.assertIsNotNone(LM_GetThread())

    def test_LM_GetThreadEx(self):
        # def LM_GetThreadEx(pproc: lm_process_t) -> Optional[lm_thread_t]:
        self.assertIsNotNone(LM_GetThreadEx(self.ex_program))

    def test_LM_GetThreadProcess(self):
        # def LM_GetThreadProcess(pthr: lm_thread_t) -> Optional[lm_process_t]:
        self.assertIsNotNone(LM_GetThreadProcess(LM_GetThread()))

    # def LM_HookCode(from_: int, to: int) -> Tuple[int, int]:
    # TODO

    # def LM_HookCodeEx(pproc: lm_process_t, from_: int, to: int) -> Tuple[int, int]:
    # TODO

    def test_LM_IsProcessAlive(self):
        # def LM_IsProcessAlive(pproc: lm_process_t) -> bool:
        self.assertTrue(LM_IsProcessAlive(self.ex_program))

    def test_LM_LoadModule(self):
        # def LM_LoadModule(modpath: str) -> Optional[lm_module_t]:
        self.assertIsNotNone(LM_LoadModule(self.test_module))

    def test_LM_LoadModuleEx(self):
        # def LM_LoadModuleEx(pproc: lm_process_t, modpath: str) -> Optional[lm_module_t]:
        self.assertIsNotNone(LM_LoadModuleEx(self.ex_program, self.test_module))

    def test_LM_PatternScan(self):
        # def LM_PatternScan(pattern: bytearray, mask: str, addr: int, scansize: int) -> Optional[int]:
        self.assertIsNotNone(LM_PatternScan(self.test_pattern, self.test_mask, self.normal_program_module.base, 0x1000))

    def test_LM_PatternScanEx(self):
        # def LM_PatternScanEx(pproc: lm_process_t, pattern: bytearray, mask: str, addr: int, scansize: int) -> Optional[int]:
        self.assertIsNotNone(
            LM_PatternScanEx(self.ex_program, self.test_pattern, self.test_mask, self.ex_program_module.base, 0x1000))

    def test_LM_ProtMemory(self):
        # def LM_ProtMemory(addr: int, size: int, prot: lm_prot_t) -> Optional[lm_prot_t]:
        self.assertIsNotNone(LM_ProtMemory(self.normal_program_module.base, self.test_size, self.prot_flag))

    def test_LM_ProtMemoryEx(self):
        # def LM_ProtMemoryEx(pproc: lm_process_t, addr: int, size: int, prot: lm_prot_t) -> Optional[lm_prot_t]:
        self.assertIsNotNone(
            LM_ProtMemoryEx(self.ex_program, self.ex_program_module.base, self.test_size, self.prot_flag))

    def test_LM_ReadMemory(self):
        # def LM_ReadMemory(src: int, size: int) -> Optional[bytearray]:
        self.assertIsNotNone(LM_ReadMemory(self.normal_program_module.base, 8))

    def test_LM_ReadMemoryEx(self):
        # def LM_ReadMemoryEx(pproc: lm_process_t, src: int, size: int) -> Optional[bytearray]:
        self.assertIsNotNone(LM_ReadMemoryEx(self.ex_program, self.ex_program_module.base, 8))

    def test_LM_SetMemory(self):
        # def LM_SetMemory(dst: int, byte: bytes, size: int) -> bool:
        self.assertTrue(LM_SetMemory(self.normal_program_module.base, bytearray(b"\x00"), 1))

    # def LM_SetMemoryEx(pproc: lm_process_t, dst: int, byte: bytes, size: int) -> bool:
    # TODO: BUG HERE?
    # print(LM_SetMemoryEx(ex_program, ex_program_module.base, bytearray(b"\x00"), 1))

    def test_LM_SigScan(self):
        # def LM_SigScan(sig: str, addr: int, scansize: int) -> Optional[int]:
        self.assertIsNotNone(LM_SigScan("nop", self.normal_program_module.base, 0x1000))

    def test_LM_SigScanEx(self):
        # def LM_SigScanEx(pproc: lm_process_t, sig: str, addr: int, scansize: int) -> Optional[int]:
        self.assertIsNotNone(LM_SigScanEx(self.ex_program, "nop", self.ex_program_module.base, 0x1000))

    # def LM_UnhookCode(from_: int, trampoline: Tuple[int, int]) -> None:
    # TODO

    # def LM_UnhookCodeEx(pproc: lm_process_t, from_: int, trampoline: Tuple[int, int]) -> None:
    # TODO

    def test_LM_UnloadModule(self):
        # def LM_UnloadModule(pmod: lm_module_t) -> Optional[bool]:
        mod = LM_LoadModule(self.test_module)
        self.assertTrue(LM_UnloadModule(mod))

    def test_LM_UnloadModuleEx(self):
        # def LM_UnloadModuleEx(pproc: lm_process_t, pmod: lm_module_t) -> Optional[bool]:
        mod = LM_LoadModuleEx(self.ex_program, self.test_module)
        self.assertTrue(LM_UnloadModuleEx(self.ex_program, mod))

    def test_LM_WriteMemory(self):
        # def LM_WriteMemory(dst: int, src: bytearray) -> bool:
        self.assertTrue(LM_WriteMemory(self.normal_program_module.base, bytearray(b"\x00")))

    def test_LM_WriteMemoryEx(self):
        # def LM_WriteMemoryEx(pproc: lm_process_t, dst: int, src: bytearray) -> bool:
        self.assertTrue(LM_WriteMemoryEx(self.ex_program, self.ex_program_module.base, bytearray(b"\x00")))


if __name__ == '__main__':
    unittest.main()