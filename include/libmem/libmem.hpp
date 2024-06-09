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

namespace LM {
	// Re-declarations
	typedef uint32_t Pid;
	typedef uint32_t Tid;
	typedef uint64_t Time;

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

		Process(struct lm_process_t *process);
		std::string to_string();
	};

	/// Searches for a process by its name
	std::optional<std::vector<Process>> EnumProcesses();
	std::optional<Process> FindProcess(const char *process_name);
}

#endif
