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
struct lm_symbol_t;
struct lm_segment_t;

namespace libmem {
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

	struct Symbol {
		std::string name;
		Address address;

		Symbol(const struct lm_symbol_t *symbol);
		std::string to_string() const;
	};

	struct Segment {
		Address base;
		Address end;
		size_t size;
		Prot prot;

		Segment(const struct lm_segment_t *segment);
		std::string to_string() const;
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

	// Symbol API

	/// Enumerates the symbols from a module
	std::optional<std::vector<Symbol>> EnumSymbols(const Module *module);

	/// Finds the address of a symbol within a module
	std::optional<Address> FindSymbolAddress(const Module *module, const char *symbol_name);

	/// Demangles a mangled symbol name
	std::optional<std::string> DemangleSymbol(const char *symbol_name);

	/// Enumerates the symbols from a module and demangles them
	std::optional<std::vector<Symbol>> EnumSymbolsDemangled(const Module *module);

	/// Finds the address of a demangled symbol within a module
	std::optional<Address> FindSymbolAddressDemangled(const Module *module, const char *symbol_name);

	// Segment API

	/// Enumerates the memory segments in the current process
	std::optional<std::vector<Segment>> EnumSegments();

	/// Enumerates the memory segments in a remote process
	std::optional<std::vector<Segment>> EnumSegments(const Process *process);

	/// Searches for a memory segment that a given address is within in the current process
	std::optional<Segment> FindSegment(Address address);

	/// Searches for a memory segment that a given address is within in a remote process
	std::optional<Segment> FindSegment(const Process *process, Address address);

	// Memory API

	/// Reads memory from a source address in the current process
	size_t ReadMemory(Address source, uint8_t *dest, size_t size);

	/// Reads memory from a source address in the current process
	template <typename T>
	inline T ReadMemory(Address source)
	{
		T dest;
		ReadMemory(source, reinterpret_cast<uint8_t *>(&dest), sizeof(dest));
		return dest;
	}

	/// Reads memory from a source address in a remote process
	size_t ReadMemory(const Process *process, Address source, uint8_t *dest, size_t size);

	/// Reads memory from a source address in a remote process
	template <typename T>
	inline std::optional<T> ReadMemory(const Process *process, Address source)
	{
		T dest;
		if (ReadMemory(process, source, reinterpret_cast<uint8_t *>(&dest), sizeof(dest)) != sizeof(dest))
			return std::nullopt;
		return dest;
	}

	/// Writes memory into a destination address in the current process
	size_t WriteMemory(Address dest, uint8_t *source, size_t size);

	/// Writes memory into a destination address in the current process
	template <typename T>
	inline void WriteMemory(Address dest, T source)
	{
		WriteMemory(dest, reinterpret_cast<uint8_t *>(&source), sizeof(T));
	}

	/// Writes memory into a destination address in a remote  process
	size_t WriteMemory(const Process *process, Address dest, uint8_t *source, size_t size);

	/// Writes memory into a destination address in a remote  process
	template <typename T>
	inline void WriteMemory(const Process *process, Address dest, T source)
	{
		WriteMemory(process, dest, reinterpret_cast<uint8_t *>(&source), sizeof(T));
	}

	/// Sets a memory region to a specific byte in the current process
	size_t SetMemory(Address dest, uint8_t byte, size_t size);

	/// Sets a memory region to a specific byte in a remote process
	size_t SetMemory(const Process *process, Address dest, uint8_t byte, size_t size);

	/// Changes the memory protection flags of a memory region in the current process
	std::optional<Prot> ProtMemory(Address address, size_t size, Prot prot);

	/// Changes the memory protection flags of a memory region in a remote process
	std::optional<Prot> ProtMemory(const Process *process, Address address, size_t size, Prot prot);

	/// Allocates memory in the current process (page-aligned)
	std::optional<Address> AllocMemory(size_t size, Prot prot);

	/// Allocates memory in a remote process (page-aligned)
	std::optional<Address> AllocMemory(const Process *process, size_t size, Prot prot);

	/// Frees memory allocated in the current process (page-aligned)
	bool FreeMemory(Address address, size_t size);

	/// Frees memory allocated in a remote process (page-aligned)
	bool FreeMemory(const Process *process, Address address, size_t size);

	/// Resolves a deep pointer (also known as pointer scan or pointer map) in the current process
	Address DeepPointer(Address base, const std::vector<Address> &offsets);

	/// Resolves a deep pointer (also known as pointer scan or pointer map) in the current process
	template <typename T>
	inline T *DeepPointer(Address base, const std::vector<Address> &offsets)
	{
		return reinterpret_cast<T *>(DeepPointer(base, offsets));
	}

	/// Resolves a deep pointer (also known as pointer scan or pointer map) in a remote process
	std::optional<Address> DeepPointer(const Process *process, Address base, const std::vector<Address> &offsets);

	// Scan API

	/// Scans for some data in the current process
	std::optional<Address> DataScan(std::vector<uint8_t> data, Address address, size_t scansize);

	/// Scans for some data in a remote process
	std::optional<Address> DataScan(const Process *process, std::vector<uint8_t> data, Address address, size_t scansize);

	/// Scans for a byte pattern with a mask in the current process
	std::optional<Address> PatternScan(std::vector<uint8_t> pattern, const char *mask, Address address, size_t scansize);

	/// Scans for a byte pattern with a mask in a remote process
	std::optional<Address> PatternScan(const Process *process, std::vector<uint8_t> pattern, const char *mask, Address address, size_t scansize);

	/// Scans for a byte signature in the current process (e.g "DE AD ?? BE EF")
	std::optional<Address> SigScan(const char *signature, Address address, size_t scansize);

	/// Scans for a byte signature in a remote process (e.g "DE AD ?? BE EF")
	std::optional<Address> SigScan(const Process *process, const char *signature, Address address, size_t scansize);
}

#endif
