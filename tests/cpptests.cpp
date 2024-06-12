#include <chrono>
#include <libmem/libmem.hpp>
#include <iostream>
#include <filesystem>
#include <thread>

namespace LM = libmem; // Alias libmem to a shorter namespace for convenience

using LM::Address;
using LM::Prot;
using LM::Arch;
using LM::Trampoline;
using LM::Vmt;

#ifdef _MSC_VER
	/* MSVC */
#	define LM_API_EXPORT __declspec(dllexport)
#else
	/* GCC/Clang */
#	define LM_API_EXPORT __attribute__((visibility("default")))
#endif

struct PointerBase {
	void *next;
	struct PointerLayer0 {
		char pad[0xF0];
		void *next;
	} layer0;
	struct PointerLayer1 {
		char pad[0xA0];
		int *final;
	} layer1;

	int player_health;
};

class SomeClass {
private:
	std::string name;
public:
	SomeClass(const char *name): name(name) {}
	virtual void print_name()
	{
		std::cout << "My name is: " << this->name << std::endl;
	}
};

static Vmt *vmt;
void hk_print_name(void *thisptr)
{
	std::cout << "print_name hooked!" << std::endl;
	std::cout << "Calling original 'print_name'..." << std::endl;

	vmt->GetOriginal<void (*)(void *)>(0)(thisptr);
}

void my_function(int number, char letter)
{
	std::cout << "MyNumber: " << number << std::endl;
	std::cout << "MyLetter: " << letter << std::endl;
}

static Trampoline my_function_tramp;
void hk_my_function(int number, char letter)
{
	std::cout << "Hooked 'my_function'!" << std::endl;
	std::cout << "Original Number: " << number << std::endl;
	std::cout << "Original Letter: " << letter << std::endl;
	std::cout << "Calling original function with custom parameters..." << std::endl;

	my_function_tramp.callable<void (*)(int, char)>()(1337, 'W');
}

void setup_pointer_base(PointerBase *base, Address address)
{
	auto ptrsize = sizeof(void *);
	base->next = reinterpret_cast<void *>(address + ptrsize);
	base->layer0.next = reinterpret_cast<void *>(reinterpret_cast<Address>(base->next) + sizeof(PointerBase::PointerLayer0));
	base->layer1.final = reinterpret_cast<int *>(reinterpret_cast<Address>(base->layer0.next) + sizeof(PointerBase::PointerLayer1));
	base->player_health = 10;
}

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

	auto cur_loaded_mod = LM::LoadModule(reinterpret_cast<const char *>(libpath.c_str())).value();
	std::cout << "[*] Loaded Module into Current Process: " << cur_loaded_mod.to_string() << std::endl;

	separator();

	auto loaded_mod = LM::LoadModule(&process, reinterpret_cast<const char *>(libpath.c_str())).value();
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

	separator();

	int number = 10;
	Address number_addr = reinterpret_cast<Address>(&number);
	int readnum;
	Address alloc;
	PointerBase ptrbase;
	std::vector<Address> offsets = { 0xF0, 0xA0, 0x0 };

	readnum = LM::ReadMemory<int>(number_addr);
	std::cout << "[*] Read Number: " << readnum << std::endl;

	LM::WriteMemory(number_addr, 1337);
	std::cout << "[*] Wrote Number: " << number << std::endl;

	LM::SetMemory(number_addr, 0, sizeof(number));
	std::cout << "[*] Set Number: " << number << std::endl;

	alloc = LM::AllocMemory(1024, Prot::XRW).value();
	segment = LM::FindSegment(alloc).value();
	std::cout << "[*] Allocated Memory: " << segment.to_string() << std::endl;

	LM::ProtMemory(alloc, 1024, Prot::RW);
	segment = LM::FindSegment(alloc).value();
	std::cout << "[*] Protected Memory: " << segment.to_string() << std::endl;

	std::cout << "[*] Freed Memory: " << (LM::FreeMemory(alloc, 1024) ? "OK": "Err") << std::endl;

	setup_pointer_base(&ptrbase, reinterpret_cast<Address>(&ptrbase));
	auto player_health = LM::DeepPointer<int>(reinterpret_cast<Address>(&ptrbase), offsets);
	*player_health = 1337;
	std::cout << "[*] Player Health (Modified after Deep Pointer): " << ptrbase.player_health << std::endl;

	separator();

	alloc = LM::AllocMemory(&process, 1024, Prot::XRW).value();
	segment = LM::FindSegment(&process, alloc).value();
	std::cout << "[*] Allocated Remote Memory: " << segment.to_string() << std::endl;

	LM::ProtMemory(&process, alloc, 1024, Prot::RW);
	segment = LM::FindSegment(&process, alloc).value();
	std::cout << "[*] Protected Remote Memory: " << segment.to_string() << std::endl;

	LM::WriteMemory(&process, alloc, 1337);
	readnum = LM::ReadMemory<int>(&process, alloc).value();
	std::cout << "[*] Read/Wrote Remote Memory: " << readnum << std::endl;

	LM::SetMemory(&process, alloc, 0, sizeof(int));
	readnum = LM::ReadMemory<int>(&process, alloc).value();
	std::cout << "[*] Read/Set Remote Memory: " << readnum << std::endl;

	setup_pointer_base(&ptrbase, alloc);
	LM::WriteMemory(&process, alloc, ptrbase);
	auto player_health_addr = LM::DeepPointer(&process, alloc, { 0xF0, 0xA0, 0x00 }).value();
	LM::WriteMemory<int>(&process, player_health_addr, 1337);
	ptrbase = LM::ReadMemory<PointerBase>(&process, alloc).value();
	std::cout << "[*] Remote Player Health (Modified after Deep Pointer): " << ptrbase.player_health << std::endl;

	std::cout << "[*] Freed Remote Memory: " << (LM::FreeMemory(&process, alloc, 1024) ? "OK": "Err") << std::endl;

	separator();

	uint8_t scan_me[] = { 0xFF, 0x0, 0xFF, 0x0, 0x10, 0x20, 0x30, 0x42, 0x0, 0x50, 0x0, 0x0 };
	Address scan_start = reinterpret_cast<Address>(scan_me);
	size_t scan_size = sizeof(scan_me);
	Address desired = reinterpret_cast<Address>(&scan_me[4]);
	Address scan;

	std::cout << "[*] Desired Scan Address: " << reinterpret_cast<void *>(desired) << std::endl;

	scan = LM::DataScan({ 0x10, 0x20, 0x30, 0x42 }, scan_start, scan_size).value();
	std::cout << "[*] Data Scan Result: " << reinterpret_cast<void *>(scan) << std::endl;

	scan = LM::PatternScan({ 0x10, 0xFF, 0x30, 0x42, 0xFF, 0x50 }, "x?xx?x", scan_start, scan_size).value();
	std::cout << "[*] Pattern Scan Result: " << reinterpret_cast<void *>(scan) << std::endl;

	scan = LM::SigScan("10 ?? 30 42 ?? 50", scan_start, scan_size).value();
	std::cout << "[*] Signature Scan Result: " << reinterpret_cast<void *>(scan) << std::endl;

	separator();

	scan_start = LM::AllocMemory(&process, scan_size, Prot::RW).value();
	LM::WriteMemory(&process, scan_start, scan_me, scan_size);

	desired = scan_start + 4;
	std::cout << "[*] Desired Remote Scan Address: " << reinterpret_cast<void *>(desired) << std::endl;

	scan = LM::DataScan(&process, { 0x10, 0x20, 0x30, 0x42 }, scan_start, scan_size).value();
	std::cout << "[*] Data Scan Result: " << reinterpret_cast<void *>(scan) << std::endl;

	scan = LM::PatternScan(&process, { 0x10, 0xFF, 0x30, 0x42, 0xFF, 0x50 }, "x?xx?x", scan_start, scan_size).value();
	std::cout << "[*] Pattern Scan Result: " << reinterpret_cast<void *>(scan) << std::endl;

	scan = LM::SigScan(&process, "10 ?? 30 42 ?? 50", scan_start, scan_size).value();
	std::cout << "[*] Signature Scan Result: " << reinterpret_cast<void *>(scan) << std::endl;

	LM::FreeMemory(&process, scan_start, scan_size);

	separator();

	auto inst = LM::Assemble("mov eax, ebx").value();
	std::cout << "[*] Assembled Instruction: " << inst.to_string() << std::endl;

	auto code_str = "push rbp; mov rbp, rsp; mov rax, 0; mov rsp, rbp; pop rbp; ret";
	auto payload = LM::Assemble(code_str, Arch::X64, 0x1000).value();
	std::cout << "[*] Assembled '" << code_str << "': [ ";
	for (auto byte: payload) {
		std::cout << std::hex << std::setw(2) << (int)byte << " ";
	}
	std::cout << std::dec << "]" << std::endl;

	auto disas_inst = LM::Disassemble(reinterpret_cast<Address>(inst.bytes.data())).value();
	std::cout << "[*] Disassembled Instruction: " << disas_inst.to_string() << std::endl;

	auto disas_insts = LM::Disassemble(reinterpret_cast<Address>(payload.data()), Arch::X64, payload.size(), 0, 0x1000).value();
	std::cout << "[*] Disassembled Payload: " << std::endl;
	for (auto inst: disas_insts) {
		std::cout << "\t" << inst.to_string() << std::endl;
	}

	// TODO: Test CodeLength

	separator();

	my_function_tramp = LM::HookCode(reinterpret_cast<Address>(my_function), reinterpret_cast<Address>(hk_my_function)).value();
	my_function(10, 'L');

	std::cout << std::endl;
	LM::UnhookCode(reinterpret_cast<Address>(my_function), my_function_tramp);
	my_function(10, 'A');

	separator();

	auto wait_message_addr = LM::FindSymbolAddress(&mod, "wait_message").value();
	std::cout << "[*] 'wait_message' address: " << reinterpret_cast<void *>(wait_message_addr) << std::endl;

	auto hk_wait_message_addr = LM::FindSymbolAddress(&mod, "hk_wait_message").value();
	std::cout << "[*] 'hk_wait_message' address: " << reinterpret_cast<void *>(hk_wait_message_addr) << std::endl;

	auto remote_tramp = LM::HookCode(&process, wait_message_addr, hk_wait_message_addr).value();
	std::cout << "[*] Hooked Remote Function! Waiting for it to run..." << std::endl;
	std::this_thread::sleep_for(std::chrono::duration(std::chrono::seconds(3)));

	LM::UnhookCode(&process, wait_message_addr, remote_tramp);
	std::cout << "[*] Unhooked Remote Function" << std::endl;

	separator();

	SomeClass *some_obj = new SomeClass("Tester");
	some_obj->print_name();
	std::cout << std::endl;

	vmt = new Vmt(*reinterpret_cast<Address **>(some_obj));
	vmt->Hook(0, reinterpret_cast<Address>(hk_print_name));
	some_obj->print_name();
	delete vmt;
	std::cout << std::endl;

	some_obj->print_name();
	delete some_obj;

	separator();

	return 0;
}
