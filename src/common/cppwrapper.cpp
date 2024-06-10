#include <libmem/libmem.hpp>
#include <libmem/libmem.h>
#include <algorithm>
#include <memory>
#include <string>
#include <sstream>

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
