#include <libmem/libmem.hpp>
#include <libmem/libmem.h>
#include <algorithm>
#include <memory>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>

using namespace libmem;

// Types

Process::Process(const struct lm_process_t *process)
{
	this->pid = process->pid;
	this->ppid = process->ppid;
	this->arch = static_cast<Arch>(process->arch);
	this->bits = process->bits;
	this->start_time = process->start_time;
	this->path = std::string(process->path);
	this->name = std::string(process->name);
}

std::string Process::to_string() const
{
	std::stringstream ss;

	ss << "Process{ pid: " << this->pid << 
		", ppid: " << this->ppid << 
		", arch: " << static_cast<int32_t>(this->arch) <<
		", bits: " << this->bits <<
		", path: \"" << this->path << "\"" <<
		", name: \"" << this->name << "\" }";
	return ss.str();
}

struct lm_process_t Process::convert() const
{
	lm_process_t proc;
	size_t len;

	proc.pid = this->pid;
	proc.ppid = this->ppid;
	proc.arch = static_cast<lm_arch_t>(this->arch);
	proc.bits = this->bits;
	proc.start_time = this->start_time;

	len = std::min(static_cast<size_t>(LM_PATH_MAX - 1), this->path.length());
	strncpy(proc.path, this->path.c_str(), len);
	proc.path[len] = '\0';

	len = std::min(static_cast<size_t>(LM_PATH_MAX - 1), this->name.length());
	strncpy(proc.name, this->name.c_str(), len);
	proc.name[len] = '\0';

	return std::move(proc);
}

// --------------------------------

Thread::Thread(const struct lm_thread_t *thread)
{
	this->tid = thread->tid;
	this->owner_pid = thread->owner_pid;
}

std::string Thread::to_string() const
{
	std::stringstream ss;

	ss << "Thread{ tid: " << this->tid <<
		", owner_pid: " << this->owner_pid << " }";
	return ss.str();
}

struct lm_thread_t Thread::convert() const
{
	lm_thread_t thread;

	thread.tid = this->tid;
	thread.owner_pid = this->owner_pid;

	return std::move(thread);
}

// --------------------------------

Module::Module(const struct lm_module_t *module)
{
	this->base = module->base;
	this->end = module->end;
	this->size = module->size;
	this->path = std::string(module->path);
	this->name = std::string(module->name);
}

std::string Module::to_string() const
{
	std::stringstream ss;

	ss << "Module{ base: " << reinterpret_cast<void *>(this->base) << 
		", end: " << reinterpret_cast<void *>(this->end) << 
		", size: " << reinterpret_cast<void *>(this->size) << 
		", path: \"" << this->path << "\"" <<
		", name: \"" << this->name << "\" }";
	return ss.str();
}

struct lm_module_t Module::convert() const
{
	lm_module_t mod;
	size_t len;

	mod.base = this->base;
	mod.end = this->end;
	mod.size = this->size;

	len = std::min(static_cast<size_t>(LM_PATH_MAX - 1), this->path.length());
	strncpy(mod.path, this->path.c_str(), len);
	mod.path[len] = '\0';

	len = std::min(static_cast<size_t>(LM_PATH_MAX - 1), this->name.length());
	strncpy(mod.name, this->name.c_str(), len);
	mod.name[len] = '\0';

	return std::move(mod);
}

// --------------------------------

Symbol::Symbol(const struct lm_symbol_t *symbol)
{
	this->name = std::string(symbol->name);
	this->address = symbol->address;
}

std::string Symbol::to_string() const
{
	std::stringstream ss;

	ss << "Symbol{ name: \"" << this->name << "\"" << 
		", address: " << reinterpret_cast<void *>(this->address) << " }";
	return ss.str();
}

// --------------------------------

Segment::Segment(const struct lm_segment_t *segment)
{
	this->base = segment->base;
	this->end = segment->end;
	this->size = segment->size;
	this->prot = static_cast<Prot>(segment->prot);
}

std::string Segment::to_string() const
{
	std::stringstream ss;

	ss << "Segment{ base: " << reinterpret_cast<void *>(this->base) << 
		", end: " << reinterpret_cast<void *>(this->end) << 
		", size: " << reinterpret_cast<void *>(this->size) <<
		", prot: " << static_cast<uint32_t>(this->prot) << " }";

	return ss.str();
}

// --------------------------------

Inst::Inst(const struct lm_inst_t *inst)
{
	this->address = inst->address;
	this->bytes = std::vector(inst->bytes, inst->bytes + inst->size);
	this->mnemonic = std::string(inst->mnemonic);
	this->op_str = std::string(inst->op_str);
}

std::string Inst::to_string() const
{
	std::stringstream ss;

	ss << reinterpret_cast<void *>(this->address) << ": " <<
		this->mnemonic << " " << this->op_str << " -> [ ";

	for (auto byte: this->bytes) {
		ss << std::hex << std::setw(2) << (int)byte << " ";
	}

	ss << "]";

	return ss.str();
}

// --------------------------------

Vmt::Vmt(Address *vtable)
{
	this->vmt = new lm_vmt_t{};
	LM_VmtNew(vtable, this->vmt);
}

Vmt::~Vmt()
{
	LM_VmtFree(this->vmt);
	delete this->vmt;
}

void Vmt::Hook(size_t from_fn_index, Address to)
{
	LM_VmtHook(this->vmt, from_fn_index, to);
}

void Vmt::Unhook(size_t fn_index)
{
	LM_VmtUnhook(this->vmt, fn_index);
}

Address Vmt::GetOriginal(size_t fn_index)
{
	return LM_VmtGetOriginal(this->vmt, fn_index);
}

void Vmt::Reset()
{
	LM_VmtReset(this->vmt);
}

/*******************************/

// Process API

lm_bool_t enum_processes_callback(lm_process_t *process, lm_void_t *arg)
{
	auto pvec = reinterpret_cast<std::vector<Process> *>(arg);
	pvec->push_back(Process(process));
	return LM_TRUE;
}

std::optional<std::vector<Process>> libmem::EnumProcesses()
{
	auto processes = std::vector<Process>();
	if (LM_EnumProcesses(enum_processes_callback, &processes) != LM_TRUE)
		return std::nullopt;
	return { std::move(processes) };
}

std::optional<Process> libmem::GetProcess()
{
	lm_process_t proc;
	if (LM_GetProcess(&proc) != LM_TRUE)
		return std::nullopt;
	return { Process(&proc) };
}

std::optional<Process> libmem::GetProcess(Pid pid)
{
	lm_process_t proc;
	if (LM_GetProcessEx(pid, &proc) != LM_TRUE)
		return std::nullopt;
	return { Process(&proc) };
}

std::optional<Process> libmem::FindProcess(const char *process_name)
{
	lm_process_t process;

	if (LM_FindProcess(process_name, &process) != LM_TRUE)
		return std::nullopt;
	return { Process(&process) };
}

bool libmem::IsProcessAlive(const Process *process)
{
	lm_process_t proc = process->convert();

	return LM_IsProcessAlive(&proc);
}

size_t libmem::GetBits()
{
	return LM_GetBits();
}

size_t libmem::GetSystemBits()
{
	return LM_GetSystemBits();
}

// --------------------------------

// Thread API

lm_bool_t enum_threads_callback(lm_thread_t *thread, lm_void_t *arg)
{
	auto pvec = reinterpret_cast<std::vector<Thread> *>(arg);
	pvec->push_back(Thread(thread));
	return LM_TRUE;
}

std::optional<std::vector<Thread>> libmem::EnumThreads()
{
	auto threads = std::vector<Thread>();
	if (LM_EnumThreads(enum_threads_callback, &threads) != LM_TRUE)
		return std::nullopt;
	return { std::move(threads) };
}

std::optional<std::vector<Thread>> libmem::EnumThreads(const Process *process)
{
	auto threads = std::vector<Thread>();
	auto proc = process->convert();

	if (LM_EnumThreadsEx(&proc, enum_threads_callback, &threads) != LM_TRUE)
		return std::nullopt;
	return { std::move(threads) };
}

std::optional<Thread> libmem::GetThread()
{
	lm_thread_t thread;

	if (LM_GetThread(&thread) != LM_TRUE)
		return std::nullopt;

	return Thread(&thread);
}

std::optional<Thread> libmem::GetThread(const Process *process)
{
	lm_thread_t thread;
	auto proc = process->convert();

	if (LM_GetThreadEx(&proc, &thread) != LM_TRUE)
		return std::nullopt;

	return Thread(&thread);
}

std::optional<Process> libmem::GetThreadProcess(const Thread *thread)
{
	lm_process_t proc;
	auto thr = thread->convert();

	if (LM_GetThreadProcess(&thr, &proc) != LM_TRUE)
		return std::nullopt;
	return Process(&proc);
}

// --------------------------------

lm_bool_t enum_modules_callback(lm_module_t *module, lm_void_t *arg)
{
	auto pvec = reinterpret_cast<std::vector<Module> *>(arg);
	pvec->push_back(Module(module));
	return LM_TRUE;
}

std::optional<std::vector<Module>> libmem::EnumModules()
{
	auto modules = std::vector<Module>();
	if (LM_EnumModules(enum_modules_callback, &modules) != LM_TRUE)
		return std::nullopt;
	return { std::move(modules) };
}

std::optional<std::vector<Module>> libmem::EnumModules(const Process *process)
{
	auto modules = std::vector<Module>();
	auto proc = process->convert();

	if (LM_EnumModulesEx(&proc, enum_modules_callback, &modules) != LM_TRUE)
		return std::nullopt;
	return { std::move(modules) };
}

std::optional<Module> libmem::FindModule(const char *name)
{
	lm_module_t mod;

	if (LM_FindModule(name, &mod) != LM_TRUE)
		return std::nullopt;
	return Module(&mod);
}

std::optional<Module> libmem::FindModule(const Process *process, const char *name)
{
	lm_module_t mod;
	auto proc = process->convert();

	if (LM_FindModuleEx(&proc, name, &mod) != LM_TRUE)
		return std::nullopt;
	return Module(&mod);
}

std::optional<Module> libmem::LoadModule(const char *path)
{
	lm_module_t mod;

	if (LM_LoadModule(path, &mod) != LM_TRUE)
		return std::nullopt;
	return Module(&mod);
}

std::optional<Module> libmem::LoadModule(const Process *process, const char *path)
{
	lm_module_t mod;
	auto proc = process->convert();

	if (LM_LoadModuleEx(&proc, path, &mod) != LM_TRUE)
		return std::nullopt;
	return Module(&mod);
}

bool libmem::UnloadModule(const Module *module)
{
	auto mod = module->convert();

	return LM_UnloadModule(&mod) == LM_TRUE;
}

bool libmem::UnloadModule(const Process *process, const Module *module)
{
	auto mod = module->convert();
	auto proc = process->convert();

	return LM_UnloadModuleEx(&proc, &mod) == LM_TRUE;
}

// --------------------------------

// Symbol API

lm_bool_t enum_symbols_callback(lm_symbol_t *symbol, lm_void_t *arg)
{
	auto pvec = reinterpret_cast<std::vector<Symbol> *>(arg);
	pvec->push_back(Symbol(symbol));
	return LM_TRUE;
}

std::optional<std::vector<Symbol>> libmem::EnumSymbols(const Module *module)
{
	auto symbols = std::vector<Symbol>();
	auto mod = module->convert();

	if (LM_EnumSymbols(&mod, enum_symbols_callback, &symbols) != LM_TRUE)
		return std::nullopt;
	return { std::move(symbols) };
}

std::optional<Address> libmem::FindSymbolAddress(const Module *module, const char *symbol_name)
{
	lm_address_t addr;
	auto mod = module->convert();

	addr = LM_FindSymbolAddress(&mod, symbol_name);
	if (addr == LM_ADDRESS_BAD)
		return std::nullopt;
	return addr;
}

std::optional<std::string> libmem::DemangleSymbol(const char *symbol_name)
{
	auto demangled_symbol = LM_DemangleSymbol(symbol_name, NULL, 0);
	if (!demangled_symbol)
		return std::nullopt;

	auto symbol = std::string(demangled_symbol);
	LM_FreeDemangledSymbol(demangled_symbol);

	return symbol;
}

std::optional<std::vector<Symbol>> libmem::EnumSymbolsDemangled(const Module *module)
{
	auto symbols = std::vector<Symbol>();
	auto mod = module->convert();

	if (LM_EnumSymbolsDemangled(&mod, enum_symbols_callback, &symbols) != LM_TRUE)
		return std::nullopt;
	return { std::move(symbols) };
}

std::optional<Address> libmem::FindSymbolAddressDemangled(const Module *module, const char *symbol_name)
{
	lm_address_t addr;
	auto mod = module->convert();

	addr = LM_FindSymbolAddressDemangled(&mod, symbol_name);
	if (addr == LM_ADDRESS_BAD)
		return std::nullopt;
	return addr;
}

// --------------------------------

// Segment API

lm_bool_t enum_segments_callback(lm_segment_t *segment, lm_void_t *arg)
{
	auto pvec = reinterpret_cast<std::vector<Segment> *>(arg);
	pvec->push_back(Segment(segment));
	return LM_TRUE;
}

std::optional<std::vector<Segment>> libmem::EnumSegments()
{
	auto segments = std::vector<Segment>();
	if (LM_EnumSegments(enum_segments_callback, &segments) != LM_TRUE)
		return std::nullopt;
	return { std::move(segments) };
}

std::optional<std::vector<Segment>> libmem::EnumSegments(const Process *process)
{
	auto segments = std::vector<Segment>();
	auto proc = process->convert();

	if (LM_EnumSegmentsEx(&proc, enum_segments_callback, &segments) != LM_TRUE)
		return std::nullopt;
	return { std::move(segments) };
}

std::optional<Segment> libmem::FindSegment(Address address)
{
	lm_segment_t segment;

	if (LM_FindSegment(address, &segment) != LM_TRUE)
		return std::nullopt;
	return Segment(&segment);
}

std::optional<Segment> libmem::FindSegment(const Process *process, Address address)
{
	lm_segment_t segment;
	auto proc = process->convert();

	if (LM_FindSegmentEx(&proc, address, &segment) != LM_TRUE)
		return std::nullopt;
	return Segment(&segment);
}

// --------------------------------

// Memory API

size_t libmem::ReadMemory(Address source, uint8_t *dest, size_t size)
{
	return LM_ReadMemory(source, dest, size);
}

size_t libmem::ReadMemory(const Process *process, Address source, uint8_t *dest, size_t size)
{
	auto proc = process->convert();

	return LM_ReadMemoryEx(&proc, source, dest, size);
}

size_t libmem::WriteMemory(Address dest, uint8_t *source, size_t size)
{
	return LM_WriteMemory(dest, source, size);
}

size_t libmem::WriteMemory(const Process *process, Address dest, uint8_t *source, size_t size)
{
	auto proc = process->convert();
	
	return LM_WriteMemoryEx(&proc, dest, source, size);
}

size_t libmem::SetMemory(Address dest, uint8_t byte, size_t size)
{
	return LM_SetMemory(dest, byte, size);
}

size_t libmem::SetMemory(const Process *process, Address dest, uint8_t byte, size_t size)
{
	auto proc = process->convert();

	return LM_SetMemoryEx(&proc, dest, byte, size);
}

std::optional<Prot> libmem::ProtMemory(Address address, size_t size, Prot prot)
{
	lm_prot_t old_prot;

	if (!LM_ProtMemory(address, size, static_cast<lm_prot_t>(prot), &old_prot))
		return std::nullopt;
	return { static_cast<Prot>(old_prot) };
}

std::optional<Prot> libmem::ProtMemory(const Process *process, Address address, size_t size, Prot prot)
{
	lm_prot_t old_prot;
	auto proc = process->convert();

	if (!LM_ProtMemoryEx(&proc, address, size, static_cast<lm_prot_t>(prot), &old_prot))
		return std::nullopt;
	return { static_cast<Prot>(old_prot) };
}

std::optional<Address> libmem::AllocMemory(size_t size, Prot prot)
{
	lm_address_t alloc;

	alloc = LM_AllocMemory(size, static_cast<lm_prot_t>(prot));
	if (alloc == LM_ADDRESS_BAD)
		return std::nullopt;
	return { alloc };
}

std::optional<Address> libmem::AllocMemory(const Process *process, size_t size, Prot prot)
{
	lm_address_t alloc;
	auto proc = process->convert();

	alloc = LM_AllocMemoryEx(&proc, size, static_cast<lm_prot_t>(prot));
	if (alloc == LM_ADDRESS_BAD)
		return std::nullopt;
	return { alloc };
}

bool libmem::FreeMemory(Address address, size_t size)
{
	return LM_FreeMemory(address, size) == LM_TRUE;
}

bool libmem::FreeMemory(const Process *process, Address address, size_t size)
{
	auto proc = process->convert();

	return LM_FreeMemoryEx(&proc, address, size) == LM_TRUE;
}

Address libmem::DeepPointer(Address base, const std::vector<Address> &offsets)
{
	auto offsets_buf = offsets.data();

	return LM_DeepPointer(base, offsets_buf, offsets.size());
}

std::optional<Address> libmem::DeepPointer(const Process *process, Address base, const std::vector<Address> &offsets)
{
	auto offsets_buf = offsets.data();
	auto proc = process->convert();
	lm_address_t address;

	address = LM_DeepPointerEx(&proc, base, offsets_buf, offsets.size());
	if (address == LM_ADDRESS_BAD)
		return std::nullopt;
	return { address };
}

// --------------------------------

// Scan API

std::optional<Address> libmem::DataScan(std::vector<uint8_t> data, Address address, size_t scansize)
{
	lm_address_t scan;

	scan = LM_DataScan(data.data(), data.size(), address, scansize);
	if (scan == LM_ADDRESS_BAD)
		return std::nullopt;
	return { scan };
}

std::optional<Address> libmem::DataScan(const Process *process, std::vector<uint8_t> data, Address address, size_t scansize)
{
	lm_address_t scan;
	auto proc = process->convert();

	scan = LM_DataScanEx(&proc, data.data(), data.size(), address, scansize);
	if (scan == LM_ADDRESS_BAD)
		return std::nullopt;
	return { scan };
}

std::optional<Address> libmem::PatternScan(std::vector<uint8_t> pattern, const char *mask, Address address, size_t scansize)
{
	lm_address_t scan;

	scan = LM_PatternScan(pattern.data(), mask, address, scansize);
	if (scan == LM_ADDRESS_BAD)
		return std::nullopt;
	return { scan };
}

std::optional<Address> libmem::PatternScan(const Process *process, std::vector<uint8_t> pattern, const char *mask, Address address, size_t scansize)
{
	lm_address_t scan;
	auto proc = process->convert();

	scan = LM_PatternScanEx(&proc, pattern.data(), mask, address, scansize);
	if (scan == LM_ADDRESS_BAD)
		return std::nullopt;
	return { scan };
}

std::optional<Address> libmem::SigScan(const char *signature, Address address, size_t scansize)
{
	lm_address_t scan;

	scan = LM_SigScan(signature, address, scansize);
	if (scan == LM_ADDRESS_BAD)
		return std::nullopt;
	return { scan };
}

std::optional<Address> libmem::SigScan(const Process *process, const char *signature, Address address, size_t scansize)
{
	lm_address_t scan;
	auto proc = process->convert();

	scan = LM_SigScanEx(&proc, signature, address, scansize);
	if (scan == LM_ADDRESS_BAD)
		return std::nullopt;
	return { scan };
}

// --------------------------------

// Assemble/Disassemble API

Arch libmem::GetArchitecture()
{
	return static_cast<Arch>(LM_GetArchitecture());
}

std::optional<Inst> libmem::Assemble(const char *code)
{
	lm_inst_t inst;

	if (LM_Assemble(code, &inst) != LM_TRUE)
		return std::nullopt;

	return { Inst(&inst) };
}

std::optional<std::vector<uint8_t>> libmem::Assemble(const char *code, Arch arch, Address runtime_address)
{
	lm_byte_t *payload;
	size_t size;

	size = LM_AssembleEx(code, static_cast<lm_arch_t>(arch), runtime_address, &payload);
	if (size == 0)
		return std::nullopt;

	auto payload_vec = std::vector(payload, payload + size);

	LM_FreePayload(payload);

	return { std::move(payload_vec) };
}

std::optional<Inst> libmem::Disassemble(Address machine_code)
{
	lm_inst_t inst;

	if (LM_Disassemble(machine_code, &inst) != LM_TRUE)
		return std::nullopt;

	return { Inst(&inst) };
}

std::optional<std::vector<Inst>> libmem::Disassemble(Address machine_code, Arch arch, size_t max_size, size_t instruction_count, Address runtime_address)
{
	lm_inst_t *insts;
	size_t count;

	count = LM_DisassembleEx(machine_code, static_cast<lm_arch_t>(arch), max_size, instruction_count, runtime_address, &insts);
	if (count == 0)
		return std::nullopt;

	std::vector<Inst> inst_vec = {};
	for (size_t i = 0; i < count; ++i)
		inst_vec.push_back(Inst(&insts[i]));

	return { inst_vec };
}

size_t libmem::CodeLength(Address machine_code, size_t min_length)
{
	return LM_CodeLength(machine_code, min_length);
}

size_t libmem::CodeLength(const Process *process, Address machine_code, size_t min_length)
{
	auto proc = process->convert();

	return LM_CodeLengthEx(&proc, machine_code, min_length);
}

// --------------------------------

// Hook API

std::optional<Trampoline> libmem::HookCode(Address from, Address to)
{
	lm_address_t tramp;
	size_t size;

	size = LM_HookCode(from, to, &tramp);
	if (size == 0)
		return std::nullopt;

	return { Trampoline { tramp, size } };
}

std::optional<RemoteTrampoline> libmem::HookCode(const Process *process, Address from, Address to)
{
	lm_address_t tramp;
	size_t size;
	auto proc = process->convert();

	size = LM_HookCodeEx(&proc, from, to, &tramp);
	if (size == 0)
		return std::nullopt;

	return { RemoteTrampoline { tramp, size } };
}

bool libmem::UnhookCode(Address from, Trampoline &trampoline)
{
	return LM_UnhookCode(from, trampoline.address, trampoline.size) == LM_TRUE;
}

bool libmem::UnhookCode(const Process *process, Address from, RemoteTrampoline &trampoline)
{
	auto proc = process->convert();

	return LM_UnhookCodeEx(&proc, from, trampoline.address, trampoline.size) == LM_TRUE;
}
