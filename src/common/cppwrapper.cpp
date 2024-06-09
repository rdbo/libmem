#include <libmem/libmem.hpp>
#include <libmem/libmem.h>
#include <algorithm>
#include <memory>
#include <string>
#include <sstream>

using namespace LM;

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

std::string Process::to_string() const {
	std::stringstream ss;

	ss << "Process{ pid: " << this->pid << 
		", ppid: " << this->ppid << 
		", arch: " << static_cast<int32_t>(this->arch) <<
		", bits: " << this->bits <<
		", path: \"" << this->path << "\"" <<
		", name: \"" << this->name << "\" }";
	return ss.str();
}

struct lm_process_t Process::convert() const {
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

/*******************************/

// Functions

lm_bool_t enum_processes_callback(lm_process_t *process, lm_void_t *arg) {
	auto pvec = reinterpret_cast<std::vector<Process> *>(arg);
	pvec->push_back(Process(process));
	return LM_TRUE;
}

std::optional<std::vector<Process>> LM::EnumProcesses()
{
	auto processes = std::vector<Process>();
	if (LM_EnumProcesses(enum_processes_callback, &processes) != LM_TRUE)
		return std::nullopt;
	return { std::move(processes) };
}

std::optional<Process> LM::GetProcess()
{
	lm_process_t proc;
	if (LM_GetProcess(&proc) != LM_TRUE)
		return std::nullopt;
	return { Process(&proc) };
}

std::optional<Process> LM::GetProcess(Pid pid)
{
	lm_process_t proc;
	if (LM_GetProcessEx(pid, &proc) != LM_TRUE)
		return std::nullopt;
	return { Process(&proc) };
}

std::optional<Process> LM::FindProcess(const char *process_name)
{
	lm_process_t process;

	if (LM_FindProcess(process_name, &process) != LM_TRUE)
		return std::nullopt;
	return { Process(&process) };
}

bool LM::IsProcessAlive(const Process *process)
{
	lm_process_t proc = process->convert();

	return LM_IsProcessAlive(&proc);
}

size_t LM::GetBits()
{
	return LM_GetBits();
}

size_t LM::GetSystemBits()
{
	return LM_GetSystemBits();
}
