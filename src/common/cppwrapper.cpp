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

/*******************************/

// Process API

lm_bool_t enum_processes_callback(lm_process_t *process, lm_void_t *arg)
{
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

// --------------------------------

// Thread API

lm_bool_t enum_threads_callback(lm_thread_t *thread, lm_void_t *arg)
{
	auto pvec = reinterpret_cast<std::vector<Thread> *>(arg);
	pvec->push_back(Thread(thread));
	return LM_TRUE;
}

std::optional<std::vector<Thread>> LM::EnumThreads()
{
	auto threads = std::vector<Thread>();
	if (LM_EnumThreads(enum_threads_callback, &threads) != LM_TRUE)
		return std::nullopt;
	return { std::move(threads) };
}

std::optional<std::vector<Thread>> LM::EnumThreads(const Process *process)
{
	auto threads = std::vector<Thread>();
	auto proc = process->convert();

	if (LM_EnumThreadsEx(&proc, enum_threads_callback, &threads) != LM_TRUE)
		return std::nullopt;
	return { std::move(threads) };
}

std::optional<Thread> LM::GetThread()
{
	lm_thread_t thread;

	if (LM_GetThread(&thread) != LM_TRUE)
		return std::nullopt;

	return Thread(&thread);
}

std::optional<Thread> LM::GetThread(const Process *process)
{
	lm_thread_t thread;
	auto proc = process->convert();

	if (LM_GetThreadEx(&proc, &thread) != LM_TRUE)
		return std::nullopt;

	return Thread(&thread);
}

std::optional<Process> LM::GetThreadProcess(const Thread *thread)
{
	lm_process_t proc;
	auto thr = thread->convert();

	if (LM_GetThreadProcess(&thr, &proc) != LM_TRUE)
		return std::nullopt;
	return Process(&proc);
}
