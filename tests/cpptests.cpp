#include <libmem/libmem.hpp>
#include <iostream>
#include <filesystem>

namespace LM = libmem; // Alias libmem to a shorter namespace for convenience

#ifdef _MSC_VER
	/* MSVC */
#	define LM_API_EXPORT __declspec(dllexport)
#else
	/* GCC/Clang */
#	define LM_API_EXPORT __attribute__((visibility("default")))
#endif

LM_API_EXPORT void separator()
{
	std::cout << "--------------------------------" << std::endl;
}

LM_API_EXPORT int main()
{
	std::cout << "[*] Process Enumeration: " << std::endl;
	auto processes = LM::EnumProcesses().value();
	for (auto process: std::vector(processes.begin(), processes.begin() + 3)) {
		std::cout << " - " << process.to_string() << std::endl;
	}
	std::cout << "..." << std::endl;
	for (auto process: std::vector(processes.end() - 3, processes.end())) {
		std::cout << " - " << process.to_string() << std::endl;
	}

	separator();

	auto cur_process = LM::GetProcess().value();
	std::cout << "[*] Current Process: " << cur_process.to_string() << std::endl;

	separator();

	std::cout << "[*] Current Process (by PID): " << LM::GetProcess(cur_process.pid).value().to_string() << std::endl;

	separator();
	
	auto process = LM::FindProcess("target").value();
	std::cout << "[*] Target Process: " << process.to_string() << std::endl;

	separator();

	std::cout << "[*] Is Target Process Alive? " << (LM::IsProcessAlive(&process) ? "Yes" : "No") << std::endl;

	separator();

	std::cout << "[*] Bits: " << LM::GetBits() << std::endl;
	std::cout << "[*] System Bits: " << LM::GetSystemBits() << std::endl;

	separator();

	std::cout << "[*] Thread Enumeration: " << std::endl;
	auto threads = LM::EnumThreads().value();

	for (auto thread: threads) {
		std::cout << " - " << thread.to_string() << std::endl;
	}

	separator();

	std::cout << "[*] Remote Thread Enumeration: " << std::endl;
	threads = LM::EnumThreads(&process).value();

	for (auto thread: threads) {
		std::cout << " - " << thread.to_string() << std::endl;
	}

	separator();

	std::cout << "[*] Current Thread: " << LM::GetThread().value().to_string() << std::endl;

	separator();

	auto thread = LM::GetThread(&process).value();
	std::cout << "[*] Remote Thread: " << thread.to_string() << std::endl;

	separator();

	std::cout << "[*] Remote Thread Owner Process: " << LM::GetThreadProcess(&thread).value().to_string() << std::endl;

	separator();

 	std::cout << "[*] Module Enumeration: " << std::endl;
 	auto modules = LM::EnumModules().value();

 	for (auto module: std::vector(modules.begin(), modules.begin() + 2)) {
		std::cout << " - " << module.to_string() << std::endl;
	}
	std::cout << "..." << std::endl;
	for (auto module: std::vector(modules.end() - 2, modules.end())) {
		std::cout << " - " << module.to_string() << std::endl;
	}

	separator();

	std::cout << "[*] Remote Module Enumeration: " << std::endl;
 	modules = LM::EnumModules(&process).value();

 	for (auto module: std::vector(modules.begin(), modules.begin() + 2)) {
		std::cout << " - " << module.to_string() << std::endl;
	}
	std::cout << "..." << std::endl;
	for (auto module: std::vector(modules.end() - 2, modules.end())) {
		std::cout << " - " << module.to_string() << std::endl;
	}

	separator();

	auto cur_mod = LM::FindModule(cur_process.name.c_str()).value();
	std::cout << "[*] Current Process Module: " << cur_mod.to_string() << std::endl;

	separator();

	auto mod = LM::FindModule(&process, process.name.c_str()).value();
	std::cout << "[*] Remote Process Module: " << mod.to_string() << std::endl;

	separator();

	auto libpath = std::filesystem::current_path() / "tests" / "libtest.so";
	std::cout << "[*] Library Path: " << libpath << std::endl;

	auto cur_loaded_mod = LM::LoadModule(libpath.c_str()).value();
	std::cout << "[*] Loaded Module into Current Process: " << cur_loaded_mod.to_string() << std::endl;

	separator();

	auto loaded_mod = LM::LoadModule(&process, libpath.c_str()).value();
	std::cout << "[*] Loaded Module into Remote Process: " << loaded_mod.to_string() << std::endl;

	separator();

	std::cout << "[*] Unloaded Module from the Current Process (result: " << (LM::UnloadModule(&cur_loaded_mod) ? "OK" : "Failed") << ")" << std::endl;

	separator();

	std::cout << "[*] Unloaded Module from Remote Process (result: " << (LM::UnloadModule(&process, &loaded_mod) ? "OK" : "Failed") << ")" << std::endl;
 
	separator();

	std::cout << "[*] Symbol Enumeration: " << std::endl;
	auto symbols = LM::EnumSymbols(&mod).value();
	for (auto symbol: std::vector(symbols.begin(), symbols.begin() + 3)) {
		std::cout << " - " << symbol.to_string() << std::endl;
	}
	std::cout << "..." << std::endl;
	for (auto symbol: std::vector(symbols.end() - 3, symbols.end())) {
		std::cout << " - " << symbol.to_string() << std::endl;
	}

	separator();

	std::cout << "[*] Symbol Enumeration (Demangled): " << std::endl;
	symbols = LM::EnumSymbolsDemangled(&mod).value();
	for (auto symbol: std::vector(symbols.begin(), symbols.begin() + 3)) {
		std::cout << " - " << symbol.to_string() << std::endl;
	}
	std::cout << "..." << std::endl;
	for (auto symbol: std::vector(symbols.end() - 3, symbols.end())) {
		std::cout << " - " << symbol.to_string() << std::endl;
	}

	separator();

	auto symbol = "main";
	std::cout << "[*] Found Symbol '" << symbol << "': " << reinterpret_cast<void *>(LM::FindSymbolAddress(&cur_mod, symbol).value()) << std::endl;

	separator();

	auto mangled = "_ZN4llvm11ms_demangle14ArenaAllocator5allocINS0_29LiteralOperatorIdentifierNodeEJEEEPT_DpOT0_";
	std::cout << "[*] Demangled Symbol '" << mangled << "': " << LM::DemangleSymbol(mangled).value() << std::endl;

	separator();

	auto demangled = "separator()";
	std::cout << "[*] Found Demangled Symbol '" << demangled << "': " << reinterpret_cast<void *>(LM::FindSymbolAddressDemangled(&cur_mod, demangled).value()) << std::endl;

	separator();

	std::cout << "[*] Segment Enumeration: " << std::endl;
	auto segments = LM::EnumSegments().value();
	for (auto segment: std::vector(segments.begin(), segments.begin() + 3)) {
		std::cout << " - " << segment.to_string() << std::endl;
	}
	std::cout << "..." << std::endl;
	for (auto segment: std::vector(segments.end() - 3, segments.end())) {
		std::cout << " - " << segment.to_string() << std::endl;
	}

	separator();

	std::cout << "[*] Remote Segment Enumeration: " << std::endl;
	segments = LM::EnumSegments(&process).value();
	for (auto segment: std::vector(segments.begin(), segments.begin() + 3)) {
		std::cout << " - " << segment.to_string() << std::endl;
	}
	std::cout << "..." << std::endl;
	for (auto segment: std::vector(segments.end() - 3, segments.end())) {
		std::cout << " - " << segment.to_string() << std::endl;
	}

	separator();

	auto segment = LM::FindSegment(cur_mod.base).value();
	std::cout << "[*] Found Segment in Current Process: " << segment.to_string() << std::endl;

	separator();

	segment = LM::FindSegment(&process, mod.base).value();
	std::cout << "[*] Found Segment in Remote Process: " << segment.to_string() << std::endl;

	return 0;
}
