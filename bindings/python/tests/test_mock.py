import unittest
from unittest.mock import patch
from libmem import *


class TestLibmemFunctions(unittest.TestCase):

    @patch('libmem._libmem.LM_FreeMemory')
    def test_LM_FreeMemory(self, mock_free_memory):
        mock_free_memory.return_value = True
        self.assertTrue(LM_FreeMemory(1234, 100))

    @patch('libmem._libmem.LM_Assemble')
    def test_LM_Assemble(self, mock_assemble):
        mock_assemble.return_value = lm_inst_t()
        self.assertIsInstance(LM_Assemble("mov eax, ebx"), lm_inst_t)
        mock_assemble.return_value = None
        self.assertIsNone(LM_Assemble("invalid code"))

    @patch('libmem._libmem.LM_DemangleSymbol')
    def test_LM_DemangleSymbol(self, mock_demangle):
        mock_demangle.return_value = "demangled_symbol"
        self.assertEqual(LM_DemangleSymbol("_ZnV4testE"), "demangled_symbol")
        mock_demangle.return_value = None
        self.assertIsNone(LM_DemangleSymbol("invalid_symbol"))

    @patch('libmem._libmem.LM_EnumPagesEx')
    def test_LM_EnumPagesEx(self, mock_enum_pages_ex):
        mock_enum_pages_ex.return_value = [lm_page_t()]
        self.assertIsInstance(LM_EnumPagesEx(lm_process_t()), list)
        mock_enum_pages_ex.return_value = None
        self.assertIsNone(LM_EnumPagesEx(lm_process_t()))

    @patch('libmem._libmem.LM_EnumSymbolsDemangled')
    def test_LM_EnumSymbolsDemangled(self, mock_enum_symbols_demangled):
        mock_enum_symbols_demangled.return_value = [lm_symbol_t()]
        self.assertIsInstance(LM_EnumSymbolsDemangled(lm_module_t()), list)
        mock_enum_symbols_demangled.return_value = None
        self.assertIsNone(LM_EnumSymbolsDemangled(lm_module_t()))

    @patch('libmem._libmem.LM_ProtMemory')
    def test_LM_ProtMemory(self, mock_prot_memory):
        mock_prot_memory.return_value = lm_prot_t()
       self.assertIsInstance(LM_ProtMemory(1234, 100, lm_prot_t()), lm_prot_t)
        mock_prot_memory.return_value = None
        self.assertIsNone(LM_ProtMemory(1234, 100, lm_prot_t()))

    @patch('libmem._libmem.LM_IsProcessAlive')
    def test_LM_IsProcessAlive(self, mock_is_process_alive):
        mock_is_process_alive.return_value = True
        self.assertTrue(LM_IsProcessAlive(lm_process_t()))

    @patch('libmem._libmem.LM_SetMemory')
    def test_LM_SetMemory(self, mock_set_memory):
        mock_set_memory.return_value = True
        self.assertTrue(LM_SetMemory(1234, b'\x01', 100))

    @patch('libmem._libmem.LM_AllocMemory')
    def test_LM_AllocMemory(self, mock_alloc_memory):
        mock_alloc_memory.return_value = 1234
        self.assertEqual(LM_AllocMemory(100, 1), 1234)
        mock_alloc_memory.return_value = None
        self.assertIsNone(LM_AllocMemory(100, 1))

    @patch('libmem._libmem.LM_DataScan')
    def test_LM_DataScan(self, mock_data_scan):
        mock_data_scan.return_value = 1234
        self.assertEqual(LM_DataScan(bytearray(b'\x00\x01\x02'), 0, 3), 1234)
        mock_data_scan.return_value = None
        self.assertIsNone(LM_DataScan(bytearray(b'\x00\x01\x02'), 0, 3))

    @patch('libmem.LM_UnhookCode')
    def test_LM_UnhookCode(self, mock_unhook_code):
        mock_unhook_code.return_value = None
        self.assertIsNone(LM_UnhookCode(1234, (0, 1)))

    @patch('libmem._libmem.LM_SetMemoryEx')
    def test_LM_SetMemoryEx(self, mock_set_memory_ex):
        mock_set_memory_ex.return_value = True
        self.assertTrue(LM_SetMemoryEx(lm_process_t(), 1234, b'\x01', 100))

    @patch('libmem._libmem.LM_EnumThreads')
    def test_LM_EnumThreads(self, mock_enum_threads):
        mock_enum_threads.return_value = [lm_thread_t()]
        self.assertIsInstance(LM_EnumThreads(), list)
        mock_enum_threads.return_value = None
        self.assertIsNone(LM_EnumThreads())

    @patch('libmem._libmem.LM_SigScanEx')
    def test_LM_SigScanEx(self, mock_sigscan_ex):
        mock_sigscan_ex.return_value = 1234
        self.assertEqual(LM_SigScanEx(lm_process_t(), "signature", 0, 100), 1234)
        mock_sigscan_ex.return_value = None
        self.assertIsNone(LM_SigScanEx(lm_process_t(), "signature", 0, 100))

    @patch('libmem._libmem.LM_GetThreadProcess')
    def test_LM_GetThreadProcess(self, mock_get_thread_process):
        mock_get_thread_process.return_value = lm_process_t()
        self.assertIsInstance(LM_GetThreadProcess(lm_thread_t()), lm_process_t)
        mock_get_thread_process.return_value = None
        self.assertIsNone(LM_GetThreadProcess(lm_thread_t()))

    @patch('libmem._libmem.LM_EnumPages')
    def test_LM_EnumPages(self, mock_enum_pages):
        mock_enum_pages.return_value = [lm_page_t()]
        self.assertIsInstance(LM_EnumPages(), list)
        mock_enum_pages.return_value = None
        self.assertIsNone(LM_EnumPages())

    @patch('libmem._libmem.LM_ReadMemoryEx')
    def test_LM_ReadMemoryEx(self, mock_read_memory_ex):
        mock_read_memory_ex.return_value = bytearray(b"\x00\x01\x02")
        self.assertEqual(LM_ReadMemoryEx(lm_process_t(), 0, 3), bytearray(b"\x00\x01\x02"))
        mock_read_memory_ex.return_value = None
        self.assertIsNone(LM_ReadMemoryEx(lm_process_t(), 0, 3))

    @patch('libmem._libmem.LM_EnumModulesEx')
    def test_LM_EnumModulesEx(self, mock_enum_modules_ex):
        mock_enum_modules_ex.return_value = [lm_module_t()]
        self.assertIsInstance(LM_EnumModulesEx(lm_process_t()), list)
        mock_enum_modules_ex.return_value = None
        self.assertIsNone(LM_EnumModulesEx(lm_process_t()))

    @patch('libmem._libmem.LM_HookCodeEx')
    def test_LM_HookCodeEx(self, mock_hook_code_ex):
        mock_hook_code_ex.return_value = (1234, 5678)
        self.assertEqual(LM_HookCodeEx(lm_process_t(), 1234, 5678), (1234, 5678))

    @patch('libmem._libmem.LM_CodeLength')
    def test_LM_CodeLength(self, mock_code_length):
        mock_code_length.return_value = 10
        self.assertEqual(LM_CodeLength(0x1234, 5), 10)
        mock_code_length.return_value = None
        self.assertIsNone(LM_CodeLength(0x1234, 5))

    @patch('libmem._libmem.LM_FreeMemoryEx')
    def test_LM_FreeMemoryEx(self, mock_free_memory_ex):
        mock_free_memory_ex.return_value = True
        self.assertTrue(LM_FreeMemoryEx(lm_process_t(), 1234, 100))

    @patch('libmem._libmem.LM_DisassembleEx')
    def test_LM_DisassembleEx(self, mock_disassemble_ex):
        mock_disassemble_ex.return_value = [lm_inst_t()]
        self.assertIsInstance(LM_DisassembleEx(0x1234, 32, 100, 10, 0x1234), list)
        mock_disassemble_ex.return_value = None
        self.assertIsNone(LM_DisassembleEx(0x1234, 32, 100, 10, 0x1234))

    @patch('libmem._libmem.LM_CodeLengthEx')
    def test_LM_CodeLengthEx(self, mock_code_length_ex):
        mock_code_length_ex.return_value = 10
        self.assertEqual(LM_CodeLengthEx(lm_process_t(), 0x1234, 5), 10)
        mock_code_length_ex.return_value = None
        self.assertIsNone(LM_CodeLengthEx(lm_process_t(), 0x1234, 5))

    @patch('libmem._libmem.LM_Disassemble')
    def test_LM_Disassemble(self, mock_disassemble):
        mock_disassemble.return_value = lm_inst_t()
        self.assertIsInstance(LM_Disassemble(0x1234), lm_inst_t)
        mock_disassemble.return_value = None
        self.assertIsNone(LM_Disassemble(0x1234))

    @patch('libmem._libmem.LM_GetPageEx')
    def test_LM_GetPageEx(self, mock_get_page_ex):
        mock_get_page_ex.return_value = lm_page_t()
        self.assertIsInstance(LM_GetPageEx(lm_process_t(), 0x1234), lm_page_t)
        mock_get_page_ex.return_value = None
        self.assertIsNone(LM_GetPageEx(lm_process_t(), 0x1234))

    @patch('libmem._libmem.LM_GetProcess')
    def test_LM_GetProcess(self, mock_get_process):
        mock_get_process.return_value = lm_process_t()
        self.assertIsInstance(LM_GetProcess(), lm_process_t)
        mock_get_process.return_value = None
        self.assertIsNone(LM_GetProcess())

    @patch('libmem._libmem.LM_UnloadModule')
    def test_LM_UnloadModule(self, mock_unload_module):
        mock_unload_module.return_value = None
        self.assertIsNone(LM_UnloadModule(lm_module_t()))

    @patch('libmem._libmem.LM_WriteMemory')
    def test_LM_WriteMemory(self, mock_write_memory):
        mock_write_memory.return_value = True
        self.assertTrue(LM_WriteMemory(1234, bytearray(b'\x01\x02')))

    @patch('libmem._libmem.LM_EnumThreadsEx')
    def test_LM_EnumThreadsEx(self, mock_enum_threads_ex):
        mock_enum_threads_ex.return_value = [lm_thread_t()]
        self.assertIsInstance(LM_EnumThreadsEx(lm_process_t()), list)
        mock_enum_threads_ex.return_value = None
        self.assertIsNone(LM_EnumThreadsEx(lm_process_t()))

    @patch('libmem._libmem.LM_GetThread')
    def test_LM_GetThread(self, mock_get_thread):
        mock_get_thread.return_value = lm_thread_t()
        self.assertIsInstance(LM_GetThread(), lm_thread_t)
        mock_get_thread.return_value = None
        self.assertIsNone(LM_GetThread())

    @patch('libmem._libmem.LM_LoadModuleEx')
    def test_LM_LoadModuleEx(self, mock_load_module_ex):
        mock_load_module_ex.return_value = lm_module_t()
        self.assertIsInstance(LM_LoadModuleEx(lm_process_t(), "path/to/module"), lm_module_t)
        mock_load_module_ex.return_value = None
        self.assertIsNone(LM_LoadModuleEx(lm_process_t(), "path/to/module"))

    @patch('libmem._libmem.LM_DataScanEx')
    def test_LM_DataScanEx(self, mock_data_scan_ex):
        mock_data_scan_ex.return_value = 1234
        self.assertEqual(LM_DataScanEx(lm_process_t(), bytearray(b"\x00\x01"), 0, 100), 1234)
        mock_data_scan_ex.return_value = None
        self.assertIsNone(LM_DataScanEx(lm_process_t(), bytearray(b"\x00\x01"), 0, 100))

    @patch('libmem._libmem.LM_PatternScan')
    def test_LM_PatternScan(self, mock_pattern_scan):
        mock_pattern_scan.return_value = 1234
        self.assertEqual(LM_PatternScan(bytearray(b"\x00\x01"), "xx", 0, 100), 1234)
        mock_pattern_scan.return_value = None
        self.assertIsNone(LM_PatternScan(bytearray(b"\x00\x01"), "xx", 0, 100))

    @patch('libmem._libmem.LM_FindProcess')
    def test_LM_FindProcess(self, mock_find_process):
        mock_find_process.return_value = lm_process_t()
        self.assertIsInstance(LM_FindProcess("process_name"), lm_process_t)
        mock_find_process.return_value = None
        self.assertIsNone(LM_FindProcess("process_name"))

    @patch('libmem._libmem.LM_EnumModules')
    def test_LM_EnumModules(self, mock_enum_modules):
        mock_enum_modules.return_value = [lm_module_t()]
        self.assertIsInstance(LM_EnumModules(), list)
        mock_enum_modules.return_value = None
        self.assertIsNone(LM_EnumModules())

    @patch('libmem._libmem.LM_FindSymbolAddress')
    def test_LM_FindSymbolAddress(self, mock_find_symbol_address):
        mock_find_symbol_address.return_value = 1234
        self.assertEqual(LM_FindSymbolAddress(lm_module_t(), "symbol_name"), 1234)
        mock_find_symbol_address.return_value = None
        self.assertIsNone(LM_FindSymbolAddress(lm_module_t(), "symbol_name"))

    @patch('libmem._libmem.LM_AssembleEx')
    def test_LM_AssembleEx(self, mock_assemble_ex):
        mock_assemble_ex.return_value = bytearray(b"\x90\x90")
        self.assertEqual(LM_AssembleEx("nop; nop", 32, 0), bytearray(b"\x90\x90"))
        mock_assemble_ex.return_value = None
        self.assertIsNone(LM_AssembleEx("nop; nop", 32, 0))

    @patch('libmem._libmem.LM_ReadMemory')
    def test_LM_ReadMemory(self, mock_read_memory):
        mock_read_memory.return_value = bytearray(b"\x01\x02")
        self.assertEqual(LM_ReadMemory(0x1234, 2), bytearray(b"\x01\x02"))
        mock_read_memory.return_value = None
        self.assertIsNone(LM_ReadMemory(0x1234, 2))

    @patch('libmem._libmem.LM_EnumProcesses')
    def test_LM_EnumProcesses(self, mock_enum_processes):
        mock_enum_processes.return_value = [lm_process_t()]
        self.assertIsInstance(LM_EnumProcesses(), list)
        mock_enum_processes.return_value = None
        self.assertIsNone(LM_EnumProcesses())

    @patch('libmem._libmem.LM_GetThreadEx')
    def test_LM_GetThreadEx(self, mock_get_thread_ex):
        mock_get_thread_ex.return_value = lm_thread_t()
        self.assertIsInstance(LM_GetThreadEx(lm_process_t()), lm_thread_t)
        mock_get_thread_ex.return_value = None
        self.assertIsNone(LM_GetThreadEx(lm_process_t()))

    @patch('libmem._libmem.LM_FindSymbolAddressDemangled')
    def test_LM_FindSymbolAddressDemangled(self, mock_find_symbol_address_demangled):
        mock_find_symbol_address_demangled.return_value = 1234
        self.assertEqual(LM_FindSymbolAddressDemangled(lm_module_t(), "symbol_name"), 1234)
        mock_find_symbol_address_demangled.return_value = None
        self.assertIsNone(LM_FindSymbolAddressDemangled(lm_module_t(), "symbol_name"))

    @patch('libmem._libmem.LM_WriteMemoryEx')
    def test_LM_WriteMemoryEx(self, mock_write_memory_ex):
        mock_write_memory_ex.return_value = True
        self.assertTrue(LM_WriteMemoryEx(lm_process_t(), 1234, bytearray(b"\x01\x02")))
   
    @patch('libmem._libmem.LM_SigScan')
    def test_LM_SigScan(self, mock_sig_scan):
        mock_sig_scan.return_value = 1234
        self.assertEqual(LM_SigScan("signature", 0, 100), 1234)
        mock_sig_scan.return_value = None
        self.assertIsNone(LM_SigScan("signature", 0, 100))
   
    @patch('libmem._libmem.LM_EnumSymbols')
    def test_LM_EnumSymbols(self, mock_enum_symbols):
        mock_enum_symbols.return_value = lm_symbol_t()
        self.assertIsInstance(LM_EnumSymbols(lm_module_t()), lm_symbol_t)
        mock_enum_symbols.return_value = None
        self.assertIsNone(LM_EnumSymbols(lm_module_t()))
   
    @patch('libmem._libmem.LM_UnhookCodeEx')
    def test_LM_UnhookCodeEx(self, mock_unhook_code_ex):
        mock_unhook_code_ex.return_value = None
        self.assertIsNone(LM_UnhookCodeEx(lm_process_t(), 1234, (5678, 9012)))
   
    @patch('libmem._libmem.LM_AllocMemoryEx')
    def test_LM_AllocMemoryEx(self, mock_alloc_memory_ex):
        mock_alloc_memory_ex.return_value = 1234
        self.assertEqual(LM_AllocMemoryEx(lm_process_t(), 100, 1), 1234)
        mock_alloc_memory_ex.return_value = None
        self.assertIsNone(LM_AllocMemoryEx(lm_process_t(), 100, 1))


if __name__ == '__main__':
    unittest.main()
