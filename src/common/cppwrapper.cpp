#include <algorithm>
#include <libmem/libmem.hpp>
#include <libmem/libmem.h>
#include <memory>
#include <string>
#include <sstream>

using namespace lm;

// Types

std::string Process::to_string() {
	std::stringstream ss;

	ss << "Process{ pid: " << this->pid << 
		", ppid: " << this->ppid << 
		", arch: " << static_cast<int32_t>(this->arch) <<
		", bits: " << this->bits <<
		", path: \"" << this->path << "\"" <<
		", name: \"" << this->name << "\" }";
	return ss.str();
}

Process::Process(struct lm_process_t *process)
{
	this->pid = process->pid;
	this->ppid = process->ppid;
	this->arch = static_cast<Arch>(process->arch);
	this->bits = process->bits;
	this->start_time = process->start_time;
	this->path = std::string(process->path);
	this->name = std::string(process->name);
}

/*******************************/

// Functions

lm_bool_t enum_processes_callback(lm_process_t *process, lm_void_t *arg) {
	auto pvec = reinterpret_cast<std::vector<Process> *>(arg);
	pvec->push_back(Process(process));
	return LM_TRUE;
}

std::optional<std::vector<Process>> lm::enum_processes()
{
	auto processes = std::vector<Process>();
	if (LM_EnumProcesses(enum_processes_callback, &processes) != LM_TRUE)
		return std::nullopt;
	return { std::move(processes) };
}

std::optional<Process> lm::find_process(const char *process_name)
{
	lm_process_t process;

	if (LM_FindProcess(process_name, &process) != LM_TRUE)
		return std::nullopt;
	return { Process(&process) };
}
