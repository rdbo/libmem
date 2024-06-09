/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef LIBMEM_HPP
#define LIBMEM_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <optional>
#include <vector>

struct lm_process_t;
struct lm_thread_t;
struct lm_module_t;

namespace LM {
	// Re-declarations
	typedef uint32_t Pid;
	typedef uint32_t Tid;
	typedef uint64_t Time;
	typedef uintptr_t Address;

	// Wrappers
	enum class Prot: uint32_t {
		R = (1 << 0),
		W = (1 << 1),
		X = (1 << 2),
		XR = X | R,
		XW = X | W,
		RW = R | W,
		XRW = X | R | W,
	};

	enum class Arch: uint32_t {
		/* ARM */
		ARMV7 = 0, /* ARMv7 */
		ARMV8,     /* ARMv8 */
		THUMBV7,   /* ARMv7, thumb mode */
		THUMBV8,   /* ARMv8, thumb mode */

		ARMV7EB,   /* ARMv7, big endian */
		THUMBV7EB, /* ARMv7, big endian, thumb mode */
		ARMV8EB,   /* ARMv8, big endian */
		THUMBV8EB, /* ARMv8, big endian, thumb mode */

		AARCH64,   /* ARM64/AArch64 */

		/* MIPS */
		MIPS,     /* Mips32 */
		MIPS64,   /* Mips64 */
		MIPSEL,   /* Mips32, little endian */
		MIPSEL64, /* Mips64, little endian */

		/* X86 */
		X86_16, /* x86_16 */
		X86,    /* x86_32 */
		X64,    /* x86_64 */

		/* PowerPC */
		PPC32,   /* PowerPC 32 */
		PPC64,   /* PowerPC 64 */
		PPC64LE, /* PowerPC 64, little endian */

		/* SPARC */
		SPARC,   /* Sparc */
		SPARC64, /* Sparc64 */
		SPARCEL, /* Sparc, little endian */

		/* SystemZ */
		SYSZ, /* S390X */

		MAX,
	};

	struct Process {
		Pid pid;
		Pid ppid;
		Arch arch;
		size_t bits;
		Time start_time;
		std::string path;
		std::string name;

		Process(const struct lm_process_t *process);
		std::string to_string() const;
		struct lm_process_t convert() const;
	};

	struct Thread {
		Tid tid;
		Pid owner_pid;

		Thread(const struct lm_thread_t *thread);
		std::string to_string() const;
		struct lm_thread_t convert() const;
	};

	struct Module {
		Address base;
		Address end;
		size_t size;
		std::string path;
		std::string name;

		Module(const struct lm_module_t *module);
		std::string to_string() const;
		struct lm_module_t convert() const;
	};

	// Process API

	/// Searches for a process by its name
	std::optional<std::vector<Process>> EnumProcesses();

	/// Gets the current process
	std::optional<Process> GetProcess();

	/// Gets a process by its process ID
	std::optional<Process> GetProcess(Pid pid);

	/// Finds a process by its name
	std::optional<Process> FindProcess(const char *process_name);

	/// Checks if a process is alive or not
	bool IsProcessAlive(const Process *process);

	/// Gets the process architecture bits
	size_t GetBits();

	/// Gets the system architecture bits
	size_t GetSystemBits();

	// Thread API

	/// Enumerates the thread of the current process
	std::optional<std::vector<Thread>> EnumThreads();

	/// Enumerates the thread of a remote process
	std::optional<std::vector<Thread>> EnumThreads(const Process *process);

	/// Gets the current thread
	std::optional<Thread> GetThread();

	/// Gets a thread in a remote process
	std::optional<Thread> GetThread(const Process *process);

	/// Gets the process that owns a thread
	std::optional<Process> GetThreadProcess(const Thread *thread);

	// Module API

	/// Enumerates modules in the current process
	std::optional<std::vector<Module>> EnumModules();

	/// Enumerates modules in a remote process
	std::optional<std::vector<Module>> EnumModules(const Process *process);

	/// Searches for a module in the current process
	std::optional<Module> FindModule(const char *name);

	/// Searches for a module in a remote process
	std::optional<Module> FindModule(const Process *process, const char *name);

	/// Loads a module into the current process
	std::optional<Module> LoadModule(const char *path);

	/// Loads a module into a remote process
	std::optional<Module> LoadModule(const Process *process, const char *path);

	/// Unloads a module from the current process
	bool UnloadModule(const Module *module);

	/// Unloads a module from a remote process
	bool UnloadModule(const Process *process, const Module *module);
}

#endif
