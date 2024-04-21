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

#ifndef LIBMEM_H
#define LIBMEM_H

/* Export prefix for functions */
#ifdef _MSC_VER
	/* MSVC */
#	define LM_API_EXPORT __declspec(dllexport)
#else
	/* GCC/Clang */
#	define LM_API_EXPORT __attribute__((visibility("default")))
#endif

/* Import prefix for functions */
#ifdef _MSC_VER
#	define LM_API_IMPORT __declspec(dllimport)
#else
#	define LM_API_IMPORT extern
#endif

/* Resolve import/export */
#ifdef LM_EXPORT
#	define LM_API LM_API_EXPORT
#else
#	define LM_API LM_API_IMPORT
#endif

/* Calling convention */
#define LM_CALL

/* Constants */
#define LM_NULL    (0)
#define LM_NULLPTR ((void *)LM_NULL)

#define LM_PID_BAD ((lm_pid_t)-1) /* PID 0 is valid, so can't be used here. -1 could be valid, but it's unlikely */
#define LM_TID_BAD ((lm_tid_t)-1)
#define LM_ADDRESS_BAD ((lm_address_t)-1) /* Both 0 and -1 are a good idea here */

#define LM_PATH_MAX (4096) /* Fits up to 1024 4-byte UTF-8 characters */
#define LM_INST_MAX (16) /* Maximum size of a single instruction */

/* Helpers */
#define LM_ARRLEN(arr) (sizeof(arr) / sizeof(arr[0]))
#define LM_CHECK_PROT(prot) ((prot & LM_PROT_XRW) == prot)

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

/* Primitive types */
typedef void     lm_void_t;
typedef enum {
	LM_FALSE = 0,
	LM_TRUE = 1
}  lm_bool_t;
typedef uint8_t   lm_byte_t;
typedef uintptr_t lm_address_t;
typedef size_t    lm_size_t;

/* String types */
typedef char             lm_char_t; /* UTF-8 encoded character */
typedef const lm_char_t *lm_string_t;
typedef const lm_byte_t *lm_bytearray_t;

/* OS primitive types */
typedef uint32_t lm_pid_t;
typedef uint32_t lm_tid_t;
typedef uint64_t lm_time_t;

/*
 * Memory protection flags
 *
 * lm_prot_t bit mask:
 *
 * 31 30 29 ... 2 1 0
 * 0  0  0      0 0 0
 *              W R X
 */
enum {
	LM_PROT_NONE = 0,

	LM_PROT_R = (1 << 0),
	LM_PROT_W = (1 << 1),
	LM_PROT_X = (1 << 2),

	LM_PROT_XR = LM_PROT_X | LM_PROT_R,
	LM_PROT_XW = LM_PROT_X | LM_PROT_W,
	LM_PROT_RW = LM_PROT_R | LM_PROT_W,
	LM_PROT_XRW = LM_PROT_X | LM_PROT_R | LM_PROT_W
};
typedef uint32_t lm_prot_t;

typedef struct {
	lm_pid_t  pid;
	lm_pid_t  ppid;
	lm_size_t bits;
	lm_time_t start_time; /* Process start timestamp, in milliseconds since last boot */
	lm_char_t path[LM_PATH_MAX];
	lm_char_t name[LM_PATH_MAX];
} lm_process_t;

typedef struct {
	lm_tid_t tid;
	lm_pid_t owner_pid;
} lm_thread_t;

typedef struct {
	lm_address_t base;
	lm_address_t end;
	lm_size_t    size;
	lm_char_t    path[LM_PATH_MAX];
	lm_char_t    name[LM_PATH_MAX];
} lm_module_t;

/* An allocated segment of memory */
typedef struct {
	lm_address_t base;
	lm_address_t end;
	lm_size_t    size;
	lm_prot_t    prot;
} lm_segment_t;

typedef struct {
	lm_string_t  name;
	lm_address_t address;
} lm_symbol_t;

typedef struct {
	lm_address_t address;
	lm_size_t    size;
	lm_byte_t    bytes[LM_INST_MAX];
	lm_char_t    mnemonic[32];
	lm_char_t    op_str[160];
} lm_inst_t;

/* Supported asm/disasm architectures */
/*
 *  NOTE: The architectures listed here are the ones
 *        supported by both the assembler (keystone)
 *        and the disassembler (capstone), but not
 *        necessarily fully supported by libmem.
 */
enum {
	LM_ARCH_ARM = 0,
	LM_ARCH_ARM64,
	LM_ARCH_MIPS,
	LM_ARCH_X86,
	LM_ARCH_PPC,
	LM_ARCH_SPARC,
	LM_ARCH_SYSZ,
	LM_ARCH_EVM,

	LM_ARCH_MAX,
};
typedef uint32_t lm_arch_t;

/* Virtual method table (VMT) */
typedef struct lm_vmt_entry_t {
	lm_address_t           orig_func;
	lm_size_t              index;
	struct lm_vmt_entry_t *next;
} lm_vmt_entry_t;

typedef struct {
	lm_address_t   *vtable;
	lm_vmt_entry_t *hkentries;
} lm_vmt_t;

/*
 * API guidelines
 *
 * 1.  User facing functions should return when receiving bad parameters.
 *
 * 2.  Internal functions should 'assert' to check for bad parameters.
 *
 * 3.  Immutable struct pointers should be 'const'.
 *
 * 4.  Immutable strings should be 'lm_string_t'.
 *
 * 5.  Output variable pointers in functions should be at the end, unless
 *     it doesn't make sense to put it there (for example, when there is
 *     a size parameter after a mutable buffer).
 *
 * 6.  All user facing functions should have the 'LM_API' prefix for
 *     automatic importing and exporting.
 *
 * 7.  All user facing callables should have the 'LM_CALL' infix to ensure 
 *     that the calling convention for all callables is the same.
 *     This includes callbacks.
 *
 * 8.  Functions that run callbacks should have an 'lm_void_t *arg' argument
 *     so that the caller can pass values into the callback without globals
 *     or hacks.
 *
 * 9.  All user facing functions should have the 'LM_' prefix before their name,
 *     and after that, they should be PascalCase.
 *
 * 10. All user facing types should have the 'lm_' prefix before their name.
 *     After that, they should be snake_case, and also end with '_t'.
 *
 * 11. Exclusively output arguments in functions should have the '_out' suffix.
 */

/* Process API */

/**
 * Enumerates processes on a system and calls a callback function for each process found.
 * 
 * @param callback The callback function that will receive the current
 * process in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE`
 * to stop it.
 * @param arg The user-defined data structure that will be passed to the
 * callback function along with the `lm_process_t` structure.
 * 
 * @return `LM_TRUE` on success, or `LM_FALSE` on failure.
 */
LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *process,
					       lm_void_t    *arg),
		 lm_void_t          *arg);

/**
 * Retrieves information about the current process, including its PID,
 * parent PID, path, name, start time, and architecture bits.
 * 
 * @param process_out A pointer to the `lm_process_t` structure that will be populated
 * with information about the current process.
 * 
 * @return `LM_TRUE` if the process information was successfully
 * retrieved or `LM_FALSE` if there was an error.
 */
LM_API lm_bool_t LM_CALL
LM_GetProcess(lm_process_t *process_out);

/**
 * Retrieves information about a specified process identified by its process ID.
 * 
 * @param pid The process ID of the process for which you want to
 * retrieve information.
 * @param process_out A pointer to the `lm_process_t` structure that will be
 * populated with information about the specified process.
 * 
 * @return `LM_TRUE` if the process information was successfully
 * retrieved or `LM_FALSE` if there was an issue during the
 * retrieval process.
 */
LM_API lm_bool_t LM_CALL
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *process_out);

/**
 * Searches for a process by name and returns whether the process was
 * found or not.
 * 
 * @param process_name The name of the process you are trying to find
 * (e.g `game.exe`). It can also be a relative path, such as
 * `/game/hello` for a process at `/usr/share/game/hello`.
 * @param process_out A pointer to the `lm_process_t` structure that will be
 * populated with information about the found process.
 * 
 * @return `LM_TRUE` if the process with the specified name was found
 * successfully or `LM_FALSE` otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_FindProcess(lm_string_t   process_name,
	       lm_process_t *process_out);

/**
 * Checks if a given process is alive based on its PID and start time.
 * 
 * @param process The process that will be checked.
 * 
 * @return `LM_TRUE` if the process specified by the input `lm_process_t`
 * is alive or `LM_FALSE` otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_IsProcessAlive(const lm_process_t *process);

/**
 * Returns the size of a pointer in bits, which corresponds to the current
 * process's bits (32 bits or 64 bits).
 * 
 * @return The size of a pointer in bits.
 */
LM_API lm_size_t LM_CALL
LM_GetBits();

/**
 * Returns the system architecture bits (32 bits or 64 bits).
 * 
 * @return The system bits (32 or 64).
 */
LM_API lm_size_t LM_CALL
LM_GetSystemBits();

/* Thread API */

/**
 * Enumerates threads in the current process and calls a callback
 * function for each thread found.
 * 
 * @param callback The callback function that will receive the current
 * thread in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE`
 * to stop it.
 * @param arg The user-defined data structure that will be passed to
 * the callback function `callback` during thread enumeration. This
 * allows you to pass additional information or context to the
 * callback function if needed.
 * 
 * @return The function `LM_EnumThreads` returns a boolean value of
 * type `lm_bool_t`, containing `LM_TRUE` if it succeeds, or
 * `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_EnumThreads(lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

/**
 * Enumerates threads of a given process and invokes a callback
 * function for each thread.
 * 
 * @param process The process you want to enumerate the threads from.
 * @param callback The callback function that will receive the current
 * thread in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE`
 * to stop it.
 * @param arg The user-defined data that can be passed to the callback
 * function. It allows you to provide additional information or
 * context to the callback function when iterating over threads in a
 * process.
 * 
 * @return The function `LM_EnumThreadsEx` returns a boolean value,
 * either `LM_TRUE` or `LM_FALSE`, depending on the success of the
 * operation.
 */
LM_API lm_bool_t LM_CALL
LM_EnumThreadsEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					       lm_void_t   *arg),
		 lm_void_t          *arg);

/**
 * Retrieves information about the thread it's running from.
 * 
 * @param thread_out A pointer to the `lm_thread_t` structure that will be populated
 * with information about the current thread, specifically the thread ID (`tid`) and
 * the process ID (`owner_pid`).
 * 
 * @return `LM_TRUE` if the thread information was successfully
 * retrieved and stored in the provided `lm_thread_t` structure.
 * Otherwise, the function returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_GetThread(lm_thread_t *thread_out);

/**
 * Retrieves information about a thread in a process.
 * 
 * @param process The process that the thread will be retrieved from.
 * @param thread_out A pointer to the `lm_thread_t` variable where the function will
 * store the thread information retrieved from the process.
 * 
 * @return `LM_TRUE` if the thread was retrieved successfully, or
 * `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_GetThreadEx(const lm_process_t *process,
	       lm_thread_t        *thread_out);

/**
 * Retrieves the process that owns a given thread.
 * 
 * @param thread The thread whose process will be retrieved.
 * @param process_out A pointer to the `lm_process_t` structure where the function
 * `LM_GetThreadProcess` will store the process information related to
 * the given thread.
 * 
 * @return `LM_TRUE` if the operation was successful or `LM_FALSE`
 * otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_GetThreadProcess(const lm_thread_t *thread,
		    lm_process_t      *process_out);

/* Module API */

/**
 * Enumerates modules in the current process and calls a callback function
 * for each module found.
 * 
 * @param callback The callback function that will receive the current module in
 * the enumeration and an extra argument. This function should return `LM_TRUE`
 * to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg An extra argument that is passed to the callback function. This allows
 * you to provide additional information or context to the callback function when
 * it is invoked during the enumeration of modules.
 * 
 * @return Returns `LM_TRUE` if the enumeration succeeds, or `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_EnumModules(lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

/**
 * Enumerates modules in a specified process and calls a callback function
 * for each module found.
 * 
 * @param process The process that the modules will be enumerated from.
 * @param callback The callback function that will receive the current module in
 * the enumeration and an extra argument. This function should return `LM_TRUE`
 * to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg An extra argument that is passed to the callback function. This allows
 * you to provide additional information or context to the callback function when
 * it is invoked during the enumeration of modules.
 * 
 * @return Returns `LM_TRUE` if the enumeration succeeds, or `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					       lm_void_t   *arg),
		 lm_void_t          *arg);

/**
 * Finds a module by name and populates the `module_out` parameter with the found module information.
 * 
 * @param name The name of the module to find (e.g `game.dll`). It can also be a
 * relative path, such as `/game/hello` for a module at `/usr/share/game/hello`.
 * @param module_out A pointer to a `lm_module_t` structure. This function populates
 * this structure with information about the found module, containing information
 * such as base, end, size, path and name.
 * 
 * @return Returns `LM_TRUE` if the module is found successfully, otherwise it
 * returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_FindModule(lm_string_t  name,
	      lm_module_t *module_out);

/**
 * Finds a module by name in a specified process and populates the `module_out` parameter with the found module information.
 * 
 * @param process The process that the module will be searched in.
 * @param name The name of the module to find (e.g `game.dll`). It can also be a
 * relative path, such as `/game/hello` for a module at `/usr/share/game/hello`.
 * @param module_out A pointer to a `lm_module_t` structure. This function populates
 * this structure with information about the found module, containing information
 * such as base, end, size, path and name.
 * 
 * @return Returns `LM_TRUE` if the module is found successfully, otherwise it
 * returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_FindModuleEx(const lm_process_t *process,
		lm_string_t         name,
		lm_module_t        *module_out);

/**
 * Loads a module from a specified path into the current process.
 * 
 * @param path The path of the module to be loaded.
 * @param module_out A pointer to a `lm_module_t` type, which is used to store information
 * about the loaded module (optional).
 * 
 * @return Returns `LM_TRUE` is the module was loaded successfully, or `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_LoadModule(lm_string_t  path,
	      lm_module_t *module_out);

/**
 * Loads a module from a specified path into a specified process.
 * 
 * @param process The process that the module will be loaded into.
 * @param path The path of the module to be loaded.
 * @param module_out A pointer to a `lm_module_t` type, which is used to store information
 * about the loaded module (optional).
 * 
 * @return Returns `LM_TRUE` is the module was loaded successfully, or `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_LoadModuleEx(const lm_process_t *process,
		lm_string_t         path,
		lm_module_t        *module_out);

/**
 * Unloads a module from the current process.
 * 
 * @param module The module that you want to unload from the process.
 * 
 * @return Returns `LM_TRUE` if the module was successfully unloaded, and `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module);

/**
 * Unloads a module from a specified process.
 * 
 * @param process The process that the module will be unloaded from.
 * @param module The module that you want to unload from the process.
 * 
 * @return Returns `LM_TRUE` if the module was successfully unloaded, and `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_UnloadModuleEx(const lm_process_t *process,
		  const lm_module_t  *module);

/* Symbol API */

/**
 * Enumerates symbols in a module and calls a callback function for each symbol found.
 * 
 * @param module The module where the symbols will be enumerated from.
 * @param callback A function pointer that will receive each symbol in the enumeration and an extra argument.
 * The callback function should return `LM_TRUE` to continue the enumeration or `LM_FALSE` to stop it.
 * @param arg A pointer to user-defined data that can be passed to the callback function.
 * It allows you to provide additional information or context.
 * 
 * @return Returns `LM_TRUE` if the enumeration succeeds, `LM_FALSE` otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_EnumSymbols(const lm_module_t  *module,
	       lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

/**
 * Finds the address of a symbol within a module.
 * 
 * @param module The module where the symbol will be looked up from.
 * @param symbol_name The name of the symbol to look up.
 * 
 * @return Returns the address of the symbol, or `LM_ADDRESS_BAD` if it fails.
 */
LM_API lm_address_t LM_CALL
LM_FindSymbolAddress(const lm_module_t *module,
		     lm_string_t        symbol_name);

/**
 * Demangles a symbol name.
 * 
 * @param symbol_name The symbol name to demangle.
 * @param demangled_buf The buffer where the demangled symbol name will be stored.
 * If this is `NULL`, the symbol will be dynamically allocated and `maxsize` is ignored.
 * @param maxsize The maximum size of the buffer where the demangled symbol name will be stored.
 * 
 * @return Returns a pointer to the demangled symbol string, or `NULL` if it fails.
 * If the symbol was dynamically allocated, you need to free it with `LM_FreeDemangledSymbol`.
 */
LM_API lm_char_t * LM_CALL
LM_DemangleSymbol(lm_string_t symbol_name,
		  lm_char_t  *demangled_buf,
		  lm_size_t   maxsize);

/**
 * Frees the memory allocated for a demangled symbol name.
 * 
 * @param symbol_name The demangled symbol name to free.
 */
LM_API lm_void_t LM_CALL
LM_FreeDemangledSymbol(lm_char_t *symbol_name);

/**
 * Enumerates symbols in a module with demangled names and calls a provided callback function for each
 * symbol found.
 *
 * @param module The module where the symbols will be enumerated from.
 * @param callback A function pointer that will receive each demangled symbol in the enumeration and
 * an extra argument. The callback function should return `LM_TRUE` to continue the enumeration or
 * `LM_FALSE` to stop it.
 * @param arg A pointer to user-defined data that can be passed to the callback function.
 * It allows you to provide additional information or context.
 * 
 * @return Returns `LM_TRUE` if the enumeration succeeds, `LM_FALSE` otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_EnumSymbolsDemangled(const lm_module_t  *module,
			lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
						      lm_void_t   *arg),
			lm_void_t          *arg);

/**
 * Finds the address of a demangled symbol within a module.
 *
 * @param module The module where the symbol will be looked up from.
 * @param symbol_name The name of the symbol to look up.
 * 
 * @return Returns the address of the symbol, or `LM_ADDRESS_BAD` if it fails.
 */
LM_API lm_address_t LM_CALL
LM_FindSymbolAddressDemangled(const lm_module_t *module,
			      lm_string_t        symbol_name);

/* Segment API */

/**
 * Enumerates the memory segments of the current process and invokes a callback function for each segment.
 *
 * @param callback A function pointer that will receive each segment in the enumeration and an extra argument.
 * The callback function should return `LM_TRUE` to continue the enumeration or `LM_FALSE` to stop it.
 * @param arg A pointer to user-defined data that can be passed to the callback function.
 * It allows you to provide additional information or context to the callback function when iterating over segments.
 *
 * @return The function returns `LM_TRUE` if the enumeration was successful, or `LM_FALSE` otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_EnumSegments(lm_bool_t (LM_CALL *callback)(lm_segment_t *segment,
                			      lm_void_t    *arg),
		lm_void_t          *arg);

/**
 * Enumerates the memory segments of a given process and invokes a callback function for each segment.
 *
 * @param process A pointer to a structure containing information about the process whose segments
 * will be enumerated.
 * @param callback A function pointer that will receive each segment in the enumeration and an extra argument.
 * The callback function should return `LM_TRUE` to continue the enumeration or `LM_FALSE` to stop it.
 * @param arg A pointer to user-defined data that can be passed to the callback function.
 * It allows you to provide additional information or context to the callback function when iterating over segments.
 *
 * @return The function returns `LM_TRUE` if the enumeration was successful, or `LM_FALSE` otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_EnumSegmentsEx(const lm_process_t *process,
                  lm_bool_t (LM_CALL *callback)(lm_segment_t *segment,
						lm_void_t    *arg),
		  lm_void_t          *arg);

/**
 * The function `LM_FindSegment` searches for a memory segment that a given address is within and populates the
 * `segment_out` parameter with the result.
 * 
 * @param address The address to search for.
 * @param segment_out A pointer to an `lm_segment_t` structure to populate with information about the
 * segment that contains the specified address.
 * 
 * @return The function returns `LM_TRUE` if the specified address is found within a segment, or `LM_FALSE` otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_FindSegment(lm_address_t  address,
	       lm_segment_t *segment_out);

/**
 * The function `LM_FindSegment` searches for a memory segment that a given address is within and populates the
 * `segment_out` parameter with the result.
 * 
 * @param process A pointer to a structure containing information about the process whose memory
 * segments will be searched.
 * @param address The address to search for.
 * @param segment_out A pointer to an `lm_segment_t` structure to populate with information about the
 * segment that contains the specified address.
 * 
 * @return The function returns `LM_TRUE` if the specified address is found within a segment, or `LM_FALSE` otherwise.
 */
LM_API lm_bool_t LM_CALL
LM_FindSegmentEx(const lm_process_t *process,
		 lm_address_t        address,
		 lm_segment_t       *segment_out);

/* Memory API */

/*
 * NOTE: Memory allocation/protection/free functions are page aligned
 *
 * NOTE: In LM_ProtMemory(Ex), the `oldprot_out` parameter contains the
 *       old protection of the first page of the whole region, which is
 *       enough for most cases. You should pick the old protections yourself
 *       with LM_FindSegments(Ex) in case of a multi-segment memory protection.
 */

/**
 * Reads memory from a source address and copies it to a destination
 * address.
 * 
 * @param source The memory address from which data will be read.
 * @param dest A pointer to a memory location where the data read from the
 * source address will be stored.
 * @param size The number of bytes to read from the memory starting at the
 * source address and write into the dest buffer.
 * 
 * @return The number of bytes read from memory.
 */
LM_API lm_size_t LM_CALL
LM_ReadMemory(lm_address_t source,
	      lm_byte_t   *dest,
	      lm_size_t    size);

/**
 * Reads memory from a process and returns the number of bytes read.
 * 
 * @param process A pointer to the process that the memory will be read from.
 * @param source The starting address in the target process from which
 * you want to read memory.
 * @param dest A pointer to the destination buffer where the memory read
 * operation will store the data read from the specified source address.
 * @param size The number of bytes to read from the memory location
 * specified by the `source` address.
 * 
 * @return The number of bytes successfully read from the specified
 * memory address in the target process. If an error occurs during the
 * read operation, it returns 0.
 */
LM_API lm_size_t LM_CALL
LM_ReadMemoryEx(const lm_process_t *process,
		lm_address_t        source,
		lm_byte_t          *dest,
		lm_size_t           size);

/**
 * Writes data from a source address to a destination address in memory.
 * 
 * @param dest The destination memory address where the data from the
 * `source` array will be written to.
 * @param source A pointer to the data that needs to be written to the
 * memory starting at the destination address `dest`.
 * @param size The number of bytes to be written from the `source`
 * array to the memory starting at the `dest` address.
 * 
 * @return The number of bytes written to the destination memory
 * address.
 */
LM_API lm_size_t LM_CALL
LM_WriteMemory(lm_address_t   dest,
	       lm_bytearray_t source,
	       lm_size_t      size);

/**
 * Writes data from a source address to a destination address in a
 * specified process.
 * 
 * @param process A pointer to a structure representing a process in the
 * system.
 * @param dest The destination address in the target process where the
 * data from the `source` array will be written to.
 * @param source A pointer to the data that needs to be written to the
 * memory of the target process.
 * @param size The number of bytes to be written from the `source`
 * bytearray to the memory address specified by `dest`.
 * 
 * @return The number of bytes that were successfully written to the
 * destination address in the process's memory. If an error occurs
 * during the write operation, it returns 0.
 */
LM_API lm_size_t LM_CALL
LM_WriteMemoryEx(const lm_process_t *process,
		 lm_address_t        dest,
		 lm_bytearray_t      source,
		 lm_size_t           size);

/**
 * Sets a specified memory region to a given byte value.
 * 
 * @param dest The destination memory address where the `byte` value will
 * be written to, starting from this address.
 * @param byte The value of the byte that will be written to the memory
 * locations starting from the `dest` address.
 * @param size The number of bytes to set in the memory starting from
 * the `dest` address.
 * 
 * @return The number of bytes that were successfully set to the
 * specified value `byte` in the memory region starting at address
 * `dest`.
 */
LM_API lm_size_t LM_CALL
LM_SetMemory(lm_address_t dest,
	     lm_byte_t    byte,
	     lm_size_t    size);

/**
 * Sets a specified memory region to a given byte value in a target
 * process.
 * 
 * @param process A pointer to the process that the memory will be set.
 * @param dest The destination address in the target process where the
 * `byte` value will be written to.
 * @param byte The value of the byte that will be written to the memory
 * locations starting from the `dest` address.
 * @param size The number of bytes to set in the memory starting from
 * the `dest` address.
 * 
 * @return The number of bytes that were successfully set to the
 * specified value `byte` in the memory region starting at address
 * `dest` in the target process. If there are any errors, it returns 0.
 */
LM_API lm_size_t LM_CALL
LM_SetMemoryEx(const lm_process_t *process,
	       lm_address_t        dest,
	       lm_byte_t           byte,
	       lm_size_t           size);


/**
 * The function sets memory protection flags for a specified memory address range.
 *
 * @param address The memory address to be protected.
 * @param size The size of memory to be protected. If the size is 0,
 * the function will default to using the system's page size for the operation.
 * @param prot The new protection flags that will be applied to the memory region
 * starting at the specified address. It is a bit mask of `LM_PROT_X`
 * (execute), `LM_PROT_R` (read), `LM_PROT_W` (write).
 * @param oldprot_out A pointer to a `lm_prot_t` type variable that will be used to
 * store the old protection flags of a memory segment before they are updated with
 * the new protection settings specified by the `prot` parameter.
 *
 * @return The function returns a boolean value, either `LM_TRUE` or `LM_FALSE`, based on the
 * success of the memory protection operation.
 */
LM_API lm_bool_t LM_CALL
LM_ProtMemory(lm_address_t address,
	      lm_size_t    size,
	      lm_prot_t    prot,
	      lm_prot_t   *oldprot_out);

/**
 * The function modifies memory protection flags for a specified address range in a given
 * process.
 *
 * @param process A pointer to the process that the memory flags will be modified from.
 * @param address The memory address to be protected.
 * @param size The size of memory to be protected. If the size is 0,
 * the function will default to using the system's page size for the operation.
 * @param prot The new protection flags that will be applied to the memory region
 * starting at the specified address. It is a bit mask of `LM_PROT_X`
 * (execute), `LM_PROT_R` (read), `LM_PROT_W` (write).
 * @param oldprot_out A pointer to a `lm_prot_t` type variable that will be used to
 * store the old protection flags of a memory segment before they are updated with
 * the new protection settings specified by the `prot` parameter.
 *
 * @return The function returns a boolean value indicating whether the memory
 * protection operation was successful or not. It returns `LM_TRUE` if the
 * operation was successful and `LM_FALSE` if it was not.
 */
LM_API lm_bool_t LM_CALL
LM_ProtMemoryEx(const lm_process_t *process,
		lm_address_t        address,
		lm_size_t           size,
		lm_prot_t           prot,
		lm_prot_t          *oldprot_out);

/**
 * The function allocates memory with a specified size and protection flags,
 * returning the allocated memory address.
 *
 * @param size The size of memory to be allocated. If the size is 0, the
 * function will allocate a full page of memory. If a specific size is
 * provided, that amount of memory will be allocated, aligned to the next
 * page size.
 * @param prot The memory protection flags for the allocated memory region.
 * It is a bit mask of `LM_PROT_X` (execute), `LM_PROT_R` (read), `LM_PROT_W`
 * (write).
 *
 * @return The function returns the memory address of the allocated memory with
 * the specified allocation options, or `LM_ADDRESS_BAD` if it fails.
 */
LM_API lm_address_t LM_CALL
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot);

/**
 * The function allocates memory in a specified process with the given size
 * and memory protection flags.
 *
 * @param process A pointer to the process that the memory will be allocated to.
 * @param size The size of memory to be allocated. If the size is 0, the
 * function will allocate a full page of memory. If a specific size is
 * provided, that amount of memory will be allocated, aligned to the next
 * page size.
 * @param prot The memory protection flags for the allocated memory region.
 * It is a bit mask of `LM_PROT_X` (execute), `LM_PROT_R` (read), `LM_PROT_W`
 * (write).
 *
 * @return The function returns a memory address of type `lm_address_t` if the
 * memory allocation is successful. If there are any issues, it returns
 * `LM_ADDRESS_BAD`.
 */
LM_API lm_address_t LM_CALL
LM_AllocMemoryEx(const lm_process_t *process,
		 lm_size_t           size,
		 lm_prot_t           prot);

/**
 * The function deallocates memory that was previously allocated with
 * `LM_AllocMemory`.
 *
 * @param alloc The address of the memory block that was previously allocated.
 * @param size The size of the memory block that was previously allocated.
 * If the size is 0, the function will use the system's page size for unmapping
 * the memory.
 *
 * @return The function returns `LM_TRUE` if the memory deallocation operation
 * is successful, and `LM_FALSE` if the operation fails.
 */
LM_API lm_bool_t LM_CALL
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size);

/**
 * The function deallocates memory that was previously allocated with
 * `LM_AllocMemoryEx` on a given process.
 *
 * @param process A pointer to the process that the memory will be deallocated from.
 * @param alloc The address of the memory block that was previously allocated
 * and needs to be freed.
 * @param size The size of the memory block that was previously allocated
 * and now needs to be freed. If the size is 0, the function will use the
 * system's page size as the default size for freeing the memory.
 *
 * @return The function returns a boolean value (`LM_TRUE` or `LM_FALSE`)
 * indicating whether the memory deallocation operation was successful or
 * not.
 */
LM_API lm_bool_t LM_CALL
LM_FreeMemoryEx(const lm_process_t *process,
		lm_address_t        alloc,
		lm_size_t           size);

/**
 * The function calculates a deep pointer address by applying a series of
 * offsets to a base address and dereferencing intermediate pointers.
 *
 * @param base The starting address from which to calculate the deep pointer.
 * @param offsets An array of offsets used to navigate through the memory addresses.
 * @param noffsets The number of offsets in the `offsets` array.
 *
 * @return The function returns a deep pointer calculated based on the provided
 * base address, offsets, and number of offsets. The function iterates through
 * the offsets, adjusting the base address and dereferencing accordingly.
 */
LM_API lm_address_t LM_CALL
LM_DeepPointer(lm_address_t        base,
	       const lm_address_t *offsets,
	       size_t              noffsets);

/**
 * The function calculates a deep pointer address by applying a series of
 * offsets to a base address and dereferencing intermediate pointers in a given
 * process's memory space.
 *
 * @param process A pointer to the process that the deep pointer will be calculated from.
 * @param base The starting address from which to calculate the deep pointer.
 * @param offsets An array of offsets used to navigate through the memory addresses.
 * @param noffsets The number of offsets in the `offsets` array.
 *
 * @return The function returns a deep pointer calculated based on the provided
 * base address, offsets, and number of offsets.

/* Scan API */

/**
 * The function scans a specified memory address range for a specific data
 * pattern and returns the address where the data is found.
 *
 * @param data The data to be scanned for in memory.
 * @param datasize The size of the data array. It indicates the number of
 * bytes that need to match consecutively in order to consider it a match.
 * @param address The starting memory address where the scanning operation
 * will begin. The function will scan a range of memory starting from this
 * address to find the data.
 * @param scansize The size of the memory region to scan starting from the
 * specified `address`. It determines the range within which the function will
 * search for a match with the provided `data` array.
 *
 * @return The function returns the memory address where a match for the
 * provided data was found. If no match is found, it returns
 * `LM_ADDRESS_BAD`.
 */
LM_API lm_address_t LM_CALL
LM_DataScan(lm_bytearray_t data,
	    lm_size_t      datasize,
	    lm_address_t   address,
	    lm_size_t      scansize);

/**
 * The function scans a specified memory address range for a specific data
 * pattern in a given process and returns the address where the data is
 * found.
 *
 * @param process The process whose memory will be scanned.
 * @param data The data to be scanned for in memory.
 * @param datasize The size of the data array. It indicates the number of
 * bytes that need to match consecutively in order to consider it a match.
 * @param address The starting memory address where the scanning operation
 * will begin. The function will scan a range of memory starting from this
 * address to find the data.
 * @param scansize The size of the memory region to scan starting from the
 * specified `address`. It determines the range within which the function will
 * search for a match with the provided `data` array.
 *
 * @return The function returns the memory address where a match for the
 * provided data was found. If no match is found, it returns
 * `LM_ADDRESS_BAD`.
 */
LM_API lm_address_t LM_CALL
LM_DataScanEx(const lm_process_t *process,
	      lm_bytearray_t      data,
	      lm_size_t           datasize,
	      lm_address_t        address,
	      lm_size_t           scansize);

/**
 * The function searches for a specific pattern in memory based on a given
 * mask.
 *
 * @param pattern The pattern to be searched for in memory.
 * @param mask The pattern mask used for scanning memory. It is used to
 * specify which bytes in the pattern should be matched against the memory
 * content. The mask can contain characters such as '?' which act as
 * wildcards, allowing any byte to be matched. You can also use 'x' to have
 * an exact match.
 * @param address The starting memory address where the scanning operation
 * will begin. The function will scan the memory starting from this address
 * to find the pattern match.
 * @param scansize The size of the memory region to scan starting from the
 * specified `address`. It determines the range within which the function
 * will search for the specified pattern based on the provided `pattern` and
 * `mask`.
 *
 * @return The function returns the memory address where a match for the
 * given pattern and mask is found within the specified scan size starting
 * from the provided address. If no match is found or if an error occurs,
 * the function returns `LM_ADDRESS_BAD`.
 */
LM_API lm_address_t LM_CALL
LM_PatternScan(lm_bytearray_t pattern,
	       lm_string_t    mask,
	       lm_address_t   address,
	       lm_size_t      scansize);

/**
 * The function `LM_PatternScanEx` searches for a specific pattern in memory in a given process
 * based on a mask.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process whose memory will be scanned.
 * @param pattern The `pattern` parameter is an array of bytes that represents the pattern you are
 * searching for in memory.
 * @param mask The `mask` parameter in the `LM_PatternScanEx` function is a string that represents the
 * pattern mask used for scanning memory. It is used to specify which bytes in the pattern should be
 * matched against the memory content. The mask can contain characters such as '?' which act as
 * wildcards, allowing any byte to be matched. You can also use 'x' to have an exact match.
 * @param address The `address` parameter in the `LM_PatternScanEx` function represents the starting
 * address in memory where the pattern scanning will begin. The function will scan the memory starting
 * from this address to find the pattern match.
 * @param scansize The `scansize` parameter in the `LM_PatternScanEx` function represents the size of the
 * memory region to scan starting from the specified `address`. It determines the range within which
 * the function will search for the specified pattern based on the provided `pattern` and `mask`.
 * 
 * @return The function `LM_PatternScanEx` returns an `lm_address_t` value, which represents the memory
 * address where a match for the given pattern and mask is found within the specified scan size
 * starting from the provided address. If no match is found or if an error occurs, the
 * function returns `LM_ADDRESS_BAD`.
 */
LM_API lm_address_t LM_CALL
LM_PatternScanEx(const lm_process_t *process,
		 lm_bytearray_t      pattern,
		 lm_string_t         mask,
		 lm_address_t        address,
		 lm_size_t           scansize);

/**
 * The function `LM_SigScan` searches for a specific signature pattern in memory starting from a given
 * address within a specified scan size.
 * 
 * @param signature The `signature` parameter is a string representing the signature to be scanned for
 * in memory. It is used to identify a specific pattern of bytes in memory. You can use `??` to match
 * against any byte, or the byte's hexadecimal value. Example: `"DE AD BE EF ?? ?? 13 37"`.
 * @param address The `address` parameter in the `LM_SigScan` function represents the starting address
 * in memory where the signature scanning will begin. This is the address from which the function will
 * start looking for a specific pattern defined by the `signature` parameter within the specified
 * `scansize`.
 * @param scansize The `scansize` parameter in the `LM_SigScan` function represents the size of the
 * memory region to scan starting from the `address` parameter. It specifies the number of bytes to
 * search for the signature pattern within the memory region.
 * 
 * @return The function `LM_SigScan` is returning the memory address `match`, which is either the
 * address of the pattern match found in the specified memory range or `LM_ADDRESS_BAD` if no match is
 * found (or an error occurs).
 */
LM_API lm_address_t LM_CALL
LM_SigScan(lm_string_t  signature,
	   lm_address_t address,
	   lm_size_t    scansize);

/**
 * The function `LM_SigScanEx` searches for a specific signature pattern in memory from a given process
 * starting from a specific address within a specified scan size.
 *
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process whose memory will be scanned.
 * @param signature The `signature` parameter is a string representing the signature to be scanned for
 * in memory. It is used to identify a specific pattern of bytes in memory. You can use `??` to match
 * against any byte, or the byte's hexadecimal value. Example: `"DE AD BE EF ?? ?? 13 37"`.
 * @param address The `address` parameter in the `LM_SigScanEx` function represents the starting address
 * in memory where the signature scanning will begin. This is the address from which the function will
 * start looking for a specific pattern defined by the `signature` parameter within the specified
 * `scansize`.
 * @param scansize The `scansize` parameter in the `LM_SigScanEx` function represents the size of the
 * memory region to scan starting from the `address` parameter. It specifies the number of bytes to
 * search for the signature pattern within the memory region.
 * 
 * @return The function `LM_SigScanEx` is returning the memory address `match`, which is either the
 * address of the pattern match found in the specified memory range or `LM_ADDRESS_BAD` if no match is
 * found (or an error occurs).
 */
LM_API lm_address_t LM_CALL
LM_SigScanEx(const lm_process_t *process,
	     lm_string_t         signature,
	     lm_address_t        address,
	     lm_size_t           scansize);

/* Assemble/Disassemble API */

/**
 * The function `LM_GetArchitecture` returns the current architecture.
 *
 * @return The function `LM_GetArchitecture` is returning the architecture
 * (`lm_arch_t`) of the system. It can be one of:
 * - `LM_ARCH_X86` for 32-bit x86.
 * - `LM_ARCH_AMD64` for 64-bit x86.
 * - Others (check the enum for `lm_arch_t`)
 */
LM_API lm_arch_t LM_CALL
LM_GetArchitecture();

/**
 * The function `LM_Assemble` assembles a single instruction into machine code
 *
 * @param code The `code` parameter is a string of the instruction to be assembled.
 * Example: `"mov eax, ebx"`.
 * @param instruction_out The `instruction_out` parameter is a pointer to a `lm_inst_t` which
 * will be populated with the assembled instruction.
 *
 * @return The function `LM_Assemble` returns `LM_TRUE` if it succeeds in assembling the instruction, and
 * populates the `instruction_out` parameter with a `lm_inst_t` that contains the assembled instruction.
 * If the instruction could not be assembled successfully, then the function returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_Assemble(lm_string_t code,
	     lm_inst_t  *instruction_out);

/**
 * The function `LM_AssembleEx` assembles one or more instructions into machine code
 * (must be deallocated with `LM_FreePayload`).
 *
 * @param code The `code` parameter is a string of the instructions to be assembled.
 * Example: `"mov eax, ebx ; jmp eax"`.
 * @param arch The `arch` parameter specifies the architecture to be assembled (`LM_ARCH_*` values).
 * @param bits The `bits` parameter specifies the bits of the architecture to be assembled.
 * It can be `32` or `64`.
 * @param runtime_address The `runtime_address` parameter is the runtime address to resolve
 * the functions (for example, relative jumps will be resolved using this address).
 * @param payload_out The `payload_out` parameter is a pointer to a variable of type
 * `lm_byte_t *` that will receive the assembled instructions (deallocate after use with
 * `LM_FreePayload`).
 *
 * @return On success, it returns the size of the assembled instructions, in bytes.
 * On failure, it returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_AssembleEx(lm_string_t  code,
              lm_arch_t    arch,
	      lm_size_t    bits,
	      lm_address_t runtime_address,
	      lm_byte_t  **payload_out);

/**
 * The function `LM_FreePayload` frees memory allocated by `LM_AssembleEx`.
 *
 * @param payload The `payload` parameter is a pointer to a buffer that was allocated by
 * `LM_AssembleEx` and needs to be freed.
 */
LM_API lm_void_t LM_CALL
LM_FreePayload(lm_byte_t *payload);

/**
 * The function `LM_Disassemble` disassembles one instruction into an `lm_inst_t` struct.
 *
 * @param machine_code The `machine_code` parameter is the address of the instruction to be
 * disassembled.
 * @param instruction_out The `instruction_out` parameter is a pointer to an `lm_inst_t` that
 * will receive the disassembled instruction.
 *
 * @return `LM_TRUE` on success, `LM_FALSE` on failure.
 */
LM_API lm_bool_t LM_CALL
LM_Disassemble(lm_address_t machine_code,
		lm_inst_t   *instruction_out);

/**
 * The function `LM_DisassembleEx` disassembles one or more instructions into an array of
 * `lm_inst_t` structs.
 *
 * @param machine_code The `machine_code` parameter is the address of the instructions to be
 * disassembled.
 * @param arch The `arch` parameter is the architecture to be disassembled (see `lm_arch_t`
 * for available architectures).
 * @param bits The `bits` parameter is the bitness of the architecture to be disassembled (32 or 64).
 * @param max_size The `max_size` parameter is the maximum number of bytes to disassemble (0 for as
 * many as possible, limited by `instruction_count`).
 * @param instruction_count The `instruction_count` parameter is the amount of instructions
 * to disassemble (0 for as many as possible, limited by `max_size`).
 * @param runtime_address The `runtime_address` parameter is the runtime address to resolve
 * the functions (for example, relative jumps will be resolved using this address).
 * @param instructions_out The `instructions_out` parameter is a pointer to a variable of type
 * `lm_inst_t *` that will receive the disassembled instructions (deallocate after use with
 * `LM_FreeInstructions`).
 *
 * @return On success, it returns the count of the instructions disassembled. On failure, it
 * returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_DisassembleEx(lm_address_t machine_code,
		 lm_arch_t    arch,
		 lm_size_t    bits,
		 lm_size_t    max_size,
		 lm_size_t    instruction_count,
		 lm_address_t runtime_address,
		 lm_inst_t  **instructions_out);

/**
 * The function `LM_FreeInstructions` deallocates the memory allocated by
 * `LM_DisassembleEx` for the disassembled instructions.
 *
 * @param instructions The `instructions` parameter is a pointer to the disassembled
 * instructions returned by `LM_DisassembleEx`.
 */
LM_API lm_void_t LM_CALL
LM_FreeInstructions(lm_inst_t *instructions);

/**
 * The function `LM_CodeLength` calculates the size aligned to the instruction length, based on a minimum size.
 *
 * @param machine_code The `machine_code` parameter is the address of the instructions.
 * @param min_length The `min_length` parameter is the minimum size to be aligned to instruction length.
 *
 * @return On success, it returns the aligned size to the next instruction's length. On failure, it returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_CodeLength(lm_address_t machine_code,
	      lm_size_t    min_length);

/**
 * The function `LM_CodeLengthEx` calculates the size aligned to the instruction length, based on a minimum size, in a remote process.
 *
 * @param process The `process` parameter is a pointer to a valid process to get the aligned length from.
 * @param machine_code The `machine_code` parameter is the address of the instructions in the remote process.
 * @param min_length The `min_length` parameter is the minimum size to be aligned to instruction length.
 *
 * @return On success, it returns the aligned size to the next instruction's length. On failure, it returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_CodeLengthEx(const lm_process_t *process,
		 lm_address_t        machine_code,
		 lm_size_t           min_length);

/* Hook API */

/**
 * The function `LM_HookCode` places a hook/detour onto the address `from`, redirecting it to the address `to`.
 * Optionally, it generates a trampoline in `trampoline_out` to call the original function.
 *
 * @param from The `from` parameter is the address where the hook will be placed.
 * @param to The `to` parameter is the address where the hook will jump to.
 * @param trampoline_out Optional pointer to an `lm_address_t` variable that will receive a trampoline/gateway to call the original function.
 *
 * @return On success, it returns the amount of bytes occupied by the hook (aligned to the nearest instruction). On failure, it returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_HookCode(lm_address_t  from,
	    lm_address_t  to,
	    lm_address_t *trampoline_out);

/**
 * The function `LM_HookCodeEx` places a hook/detour onto the address `from` in a remote process, redirecting it to the address `to`.
 * Optionally, it generates a trampoline in `trampoline_out` to call the original function in the remote process.
 *
 * @param process The `process` parameter is a pointer to a valid process to place the hook in.
 * @param from The `from` parameter is the address where the hook will be placed in the remote process.
 * @param to The `to` parameter is the address where the hook will jump to in the remote process.
 * @param trampoline_out Optional pointer to an `lm_address_t` variable that will receive a trampoline/gateway to call the
 * original function in the remote process.
 *
 * @return On success, it returns the amount of bytes occupied by the hook (aligned to the nearest instruction) in the remote process.
 * On failure, it returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_HookCodeEx(const lm_process_t *process,
	      lm_address_t        from,
	      lm_address_t        to,
	      lm_address_t       *trampoline_out);

/**
 * The function `LM_UnhookCode` removes a hook/detour placed on the address `from`, restoring it to its original state.
 * The function also frees the trampoline allocated by `LM_HookCode`.
 *
 * @param from The `from` parameter is the address where the hook was placed.
 * @param trampoline The `trampoline` parameter is the address of the trampoline generated by `LM_HookCode`.
 * @param size The `size` parameter is the amount of bytes occupied by the hook (aligned to the nearest instruction).
 *
 * @return On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_UnhookCode(lm_address_t from,
	      lm_address_t trampoline,
	      lm_size_t    size);

/**
 * The function `LM_UnhookCodeEx` removes a hook/detour placed on the address `from` in a remote process, restoring it to its original state.
 * The function also frees the trampoline allocated by `LM_HookCodeEx`.
 *
 * @param process The `process` parameter is a pointer to a valid process where the hook was placed.
 * @param from The `from` parameter is the address where the hook was placed.
 * @param trampoline The `trampoline` parameter is the address of the trampoline generated by `LM_HookCodeEx`.
 * @param size The `size` parameter is the amount of bytes occupied by the hook (aligned to the nearest instruction) in the remote process.
 *
 * @return On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_UnhookCodeEx(const lm_process_t *process,
		lm_address_t        from,
		lm_address_t        trampoline,
		lm_size_t           size);

/* Virtual Method Table API */

/**
 * The function `LM_VmtNew` creates a new VMT manager from the VMT at `vtable` into `vmt_out`.
 *
 * @param vtable The `vtable` parameter is a pointer to the VMT array to manage.
 * @param vmt_out The `vmt_out` parameter is a pointer to an uninitialized `lm_vmt_t` structure that will receive the VMT manager.
 *
 * @return On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_VmtNew(lm_address_t *vtable,
	  lm_vmt_t     *vmt_out);

/**
 * The function `LM_VmtHook` hooks the VMT function at index `from_fn_index` in the VMT managed by `vmt`,
 * changing it to `to`.
 *
 * @param vmt The `vmt` parameter is a pointer to a valid VMT manager.
 * @param from_fn_index The `from_fn_index` parameter is the index of the VMT function to hook.
 * @param to The `to` parameter is the pointer to the function that will replace the original VMT function.
 *
 * @return On success, it returns `LM_TRUE`. On failure, it returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_VmtHook(lm_vmt_t    *vmt,
	   lm_size_t    from_fn_index,
	   lm_address_t to);

/**
 * The function `LM_VmtUnhook` unhooks the VMT function at index `fn_index` in the VMT managed by `vmt`,
 * restoring the original function.
 *
 * @param vmt The `vmt` parameter is a pointer to a valid VMT manager.
 * @param fn_index The `fn_index` parameter is the index of the VMT function to unhook.
 */
LM_API lm_void_t LM_CALL
LM_VmtUnhook(lm_vmt_t *vmt,
	     lm_size_t fn_index);

/**
 * The function `LM_VmtGetOriginal` returns the original VMT function at index `fn_index` in the VMT managed by `vmt`.
 * If the function has not been hooked before, it returns the function pointer at that index in the VMT array.
 *
 * @param vmt The `vmt` parameter is a pointer to a valid VMT manager.
 * @param fn_index The `fn_index` parameter is the index of the VMT function to query.
 *
 * @return The function returns the original VMT function at index `fn_index` in the VMT managed by `vmt`.
 */
LM_API lm_address_t LM_CALL
LM_VmtGetOriginal(const lm_vmt_t *vmt,
		  lm_size_t       fn_index);

/**
 * The function `LM_VmtReset` resets all the VMT functions back to their original addresses.
 *
 * @param vmt The `vmt` parameter is a pointer to a valid VMT manager.
 */
LM_API lm_void_t LM_CALL
LM_VmtReset(lm_vmt_t *vmt);

/**
 * The function `LM_VmtFree` frees the VMT manager, restoring everything.
 *
 * @param vmt The `vmt` parameter is a pointer to a valid VMT manager.
 */
LM_API lm_void_t LM_CALL
LM_VmtFree(lm_vmt_t *vmt);

#ifdef __cplusplus
}
#endif

#endif
