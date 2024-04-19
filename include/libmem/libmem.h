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
 * The function `LM_EnumProcesses` enumerates processes on a system and calls a callback function for
 * each process.
 * 
 * @param callback The `callback` parameter in the `LM_EnumProcesses` function is a function pointer
 * that that will receive the current process in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg The `arg` parameter in the `LM_EnumProcesses` function is a pointer to a user-defined
 * data structure that will be passed to the callback function along with the `lm_process_t` structure.
 * This allows you to pass additional information or context to the callback function when processing
 * each process.
 * 
 * @return The function `LM_EnumProcesses` returns a boolean value, either `LM_TRUE` on success or
 * `LM_FALSE` on failure.
 */
LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *process,
					       lm_void_t    *arg),
		 lm_void_t          *arg);

/**
 * The function `LM_GetProcess` retrieves information about the current process, including its PID,
 * parent PID, path, name, start time, and architecture bits.
 * 
 * @param process_out The `process_out` parameter is a pointer to a `lm_process_t` structure. This
 * function populates this structure with information about the current process, such as process ID, 
 * parent process ID, process path, process name, start time, and bits.
 * 
 * @return The `LM_GetProcess` function returns a boolean value indicating whether the process
 * information was successfully retrieved or not. If the process information was successfully
 * retrieved, it returns `LM_TRUE`. If there was an error or if the process_out pointer is `NULL`, it
 * returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_GetProcess(lm_process_t *process_out);

/**
 * The function `LM_GetProcessEx` retrieves information about a specified process identified by its
 * process ID.
 * 
 * @param pid The `pid` parameter represents the process ID of the process for which you want to retrieve
 * information.
 * @param process_out The `process_out` parameter is a pointer to a `lm_process_t` structure. This
 * function populates this structure with information about the specified process, such as process ID,
 * parent process ID, process path, process name, start time, and bits.
 * 
 * @return The function `LM_GetProcessEx` returns a boolean value indicating whether the process
 * information retrieval was successful or not. If the process information was successfully retrieved,
 * it returns `LM_TRUE`. Otherwise, if there was an issue during the retrieval process, it returns
 * `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *process_out);

/**
 * The function `LM_FindProcess` searches for a process by name and returns whether the process was
 * found or not.
 * 
 * @param process_name The `process_name` parameter is a string that represents the name of the process
 * you are trying to find (e.g `game.exe`). It can also be a relative path, such as `/game/hello` for a
 * process at `/usr/share/game/hello`.
 * @param process_out The `process_out` parameter is a pointer to a `lm_process_t` structure. This
 * function populates this structure with information about the found process, such as process ID,
 * parent process ID, process path, process name, start time, and bits.This
 * 
 * @return The function `LM_FindProcess` returns a boolean value (`LM_TRUE` or `LM_FALSE`) based on
 * whether the process with the specified name was found successfully.
 */
LM_API lm_bool_t LM_CALL
LM_FindProcess(lm_string_t   process_name,
	       lm_process_t *process_out);

/**
 * The function `LM_IsProcessAlive` checks if a given process is alive based on its PID and start time.
 * 
 * @param process This structure contains information about the process that will be checked.
 * 
 * @return The function `LM_IsProcessAlive` returns a boolean value (`LM_TRUE` or `LM_FALSE`)
 * indicating whether the process specified by the input `lm_process_t *process` is alive or not.
 */
LM_API lm_bool_t LM_CALL
LM_IsProcessAlive(const lm_process_t *process);

/**
 * The function `LM_GetBits` returns the size of a pointer in bits, which corresponds to the current
 * process's bits (32 bits or 64 bits).
 * 
 * @return The function `LM_GetBits` returns the size of a pointer in bits.
 */
LM_API lm_size_t LM_CALL
LM_GetBits();

/**
 * The function `LM_GetSystemBits` returns the system architecture bits (32 bits or 64 bits).
 * 
 * @return The function `LM_GetSystemBits` returns the system bits (32 or 64).
 */
LM_API lm_size_t LM_CALL
LM_GetSystemBits();

/* Thread API */

/**
 * The function `LM_EnumThreads` enumerates threads in the current process and calls a callback function
 * for each thread found.
 * 
 * @param callback The `callback` parameter in the `LM_EnumThreads` function is a function pointer
 * that that will receive the current thread in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg The `arg` parameter is a pointer to a user-defined data structure that will be passed to
 * the callback function `callback` during thread enumeration. This allows you to provide additional
 * context or information to the callback function if needed.
 * 
 * @return The function `LM_EnumThreads` returns a boolean value of type `lm_bool_t`, containing `LM_TRUE`
 * if it succeeds, or `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_EnumThreads(lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

/**
 * The function `LM_EnumThreadsEx` enumerates threads of a given process and invokes a callback
 * function for each thread.
 * 
 * @param process The `process` parameter in the `LM_EnumThreadsEx` function is a pointer to a
 * structure of type `lm_process_t`, which contains information about the process you want to
 * enumerate the threads from.
 * @param callback The `callback` parameter in the `LM_EnumThreads` function is a function pointer
 * that that will receive the current thread in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg The `arg` parameter in the `LM_EnumThreadsEx` function is a pointer to user-defined data
 * that can be passed to the callback function. It allows you to provide additional information or
 * context to the callback function when iterating over threads in a process.
 * 
 * @return The function `LM_EnumThreadsEx` returns a boolean value, either `LM_TRUE` or `LM_FALSE`,
 * depending on the success of the operation.
 */
LM_API lm_bool_t LM_CALL
LM_EnumThreadsEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					       lm_void_t   *arg),
		 lm_void_t          *arg);

/**
 * The function `LM_GetThread` retrieves information about the thread it's running from.
 * 
 * @param thread_out The `thread_out` parameter is a pointer to a `lm_thread_t` structure. This
 * function will populate this structure with information about the current thread, specifically
 * the thread ID (`tid`) and the process ID (`owner_pid`).
 * 
 * @return The LM_GetThread function returns `LM_TRUE` if the thread information was successfully
 * retrieved and stored in the provided `lm_thread_t` structure. Otherwise, the function returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_GetThread(lm_thread_t *thread_out);

/**
 * The function `LM_GetThreadEx` retrieves information about a thread in a process.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the thread will be retrieved from.
 * @param thread_out The `thread_out` parameter is a pointer to a `lm_thread_t` variable where the
 * function will store the thread information retrieved from the process.
 * 
 * @return The function `LM_GetThreadEx` returns `LM_TRUE` if the thread was retrieved successfully, or
 * `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_GetThreadEx(const lm_process_t *process,
	       lm_thread_t        *thread_out);

/**
 * The function `LM_GetThreadProcess` retrieves the process that owns a given thread.
 * 
 * @param thread The `thread` parameter is a pointer to a structure of type `lm_thread_t`, which
 * contains information about a thread in a system.
 * @param process_out The `process_out` parameter is a pointer to a `lm_process_t` structure where the
 * function `LM_GetThreadProcess` will store the process information related to the given thread.
 * 
 * @return The function `LM_GetThreadProcess` returns a boolean value (`LM_TRUE` or `LM_FALSE`)
 * indicating whether the operation was successful.
 */
LM_API lm_bool_t LM_CALL
LM_GetThreadProcess(const lm_thread_t *thread,
		    lm_process_t      *process_out);

/* Module API */

/**
 * The function `LM_EnumModules` enumerates modules in the current process and calls a callback function
 * for each module found.
 * 
 * @param callback The `callback` parameter in the `LM_EnumModules` function is a function pointer
 * that that will receive the current module in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg The `arg` parameter in the `LM_EnumModules` function is a pointer to a user-defined data
 * structure that can be passed to the callback function `callback`. This allows you to provide
 * additional information or context to the callback function when it is invoked during the enumeration
 * of modules.
 * 
 * @return The function `LM_EnumModules` returns `LM_TRUE` is the enumeration succeeds, or `LM_FALSE`
 * if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_EnumModules(lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

/**
 * The function `LM_EnumModulesEx` enumerates modules in a specified process and calls a callback function
 * for each module found.
 * 
 * @param process The `process` parameter in the `LM_EnumModulesEx` function is a pointer to a
 * structure `lm_process_t` which is used to identify the process for which the modules are being
 * enumerated.
 * @param callback The `callback` parameter in the `LM_EnumModulesEx` function is a function pointer
 * that that will receive the current module in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg The `arg` parameter in the `LM_EnumModulesEx` function is a pointer to a user-defined
 * data structure or variable that you can pass to the callback function. This parameter allows you to
 * provide additional context or data to the callback function when iterating over modules in a
 * process.
 * 
 * @return The function returns `LM_TRUE` if the enumeration succeeds or `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					       lm_void_t   *arg),
		 lm_void_t          *arg);

/**
 * The function `LM_FindModule` searches for a module by name and populates the `module_out` parameter with
 * the found module information.
 * 
 * @param name The `name` parameter is a string representing the name of the module that you are trying
 * to find (e.g `game.dll`). It can also be a relative path, such as `/game/hello` for a module at `/usr/share/game/hello`.
 * @param module_out The `module_out` parameter is a pointer to a `lm_module_t` structure. This function
 * populates this structure with information about the found module, containing information such as base,
 * end, size, path and name.
 * 
 * @return The function `LM_FindModule` returns `LM_TRUE` if the module is found successfully,
 * otherwise it returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_FindModule(lm_string_t  name,
	      lm_module_t *module_out);

/**
 * The function `LM_FindModuleEx` searches for a module by name and populates the `module_out` parameter with
 * the found module information.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the module will be retrieved from.
 * @param name The `name` parameter is a string representing the name of the module that you are trying
 * to find (e.g `game.dll`). It can also be a relative path, such as `/game/hello` for a module at `/usr/share/game/hello`.
 * @param module_out The `module_out` parameter is a pointer to a `lm_module_t` structure. This function
 * populates this structure with information about the found module, containing information such as base,
 * end, size, path and name.
 * 
 * @return The function `LM_FindModuleEx` returns `LM_TRUE` if the module is found successfully,
 * otherwise it returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_FindModuleEx(const lm_process_t *process,
		lm_string_t         name,
		lm_module_t        *module_out);

/**
 * The LM_LoadModule function loads a module from a specified path into the current process.
 * 
 * @param path The `path` parameter is a string that represents the file path of the module to be
 * loaded.
 * @param module_out The `module_out` parameter is a pointer to a `lm_module_t` type, which is used to
 * store information about the loaded module (optional).
 * 
 * @return The function returns `LM_TRUE` is the module was loaded successfully, or `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_LoadModule(lm_string_t  path,
	      lm_module_t *module_out);

/**
 * The LM_LoadModule function loads a module from a specified path into the specified process.
 *
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the module will be loaded into.
 * @param path The `path` parameter is a string that represents the file path of the module to be
 * loaded.
 * @param module_out The `module_out` parameter is a pointer to a `lm_module_t` type, which is used to
 * store information about the loaded module (optional).
 * 
 * @return The function returns `LM_TRUE` is the module was loaded successfully, or `LM_FALSE` if it fails.
 */
LM_API lm_bool_t LM_CALL
LM_LoadModuleEx(const lm_process_t *process,
		lm_string_t         path,
		lm_module_t        *module_out);

/**
 * The function `LM_UnloadModule` unloads a module from the current process.
 * 
 * @param module The `module` parameter represents the module that you want to unload from the process.
 * 
 * @return The function `LM_UnloadModule` returns `LM_TRUE` if the module was successfully unloaded, and
 * `LM_FALSE` if there was an error.
 */
LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module);

/**
 * The function `LM_UnloadModuleEx` unloads a module from the current process.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the module will be unloaded from.
 * @param module The `module` parameter represents the module that you want to unload from the process.
 * 
 * @return The function `LM_UnloadModuleEx` returns `LM_TRUE` if the module was successfully unloaded, and
 * `LM_FALSE` if there was an error.
 */
LM_API lm_bool_t LM_CALL
LM_UnloadModuleEx(const lm_process_t *process,
		  const lm_module_t  *module);

/* Symbol API */

/**
 * The function `LM_EnumSymbols` enumerates symbols in a module and calls a callback function for each
 * symbol found.
 * 
 * @param module The `module` parameter is a pointer to a structure of type `lm_module_t`, which
 * represents the module where the symbols will be enumerated from.
 * @param callback The `callback` parameter in the `LM_EnumSymbols` function is a function pointer
 * that that will receive the current symbol in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg The `arg` parameter in the `LM_EnumSymbols` function is a pointer to a user-defined data
 * structure or variable that will be passed to the callback function `callback` for each symbol that
 * is enumerated. This allows the user to provide additional context or data that may be needed during
 * the symbol
 * 
 * @return The function `LM_EnumSymbols` returns `LM_TRUE` if the enumeration succeeds. Otherwise,
 * it returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_EnumSymbols(const lm_module_t  *module,
	       lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

/**
 * The function `LM_FindSymbolAddress` searches for the address of a symbol within a given module.
 * 
 * @param module The `module` parameter is a pointer to a structure of type `lm_module_t`, which
 * represents the module where the symbol will be looked up from.
 * @param symbol_name The `symbol_name` parameter is a string representing the name of the symbol
 * (function, variable, etc) whose address you want to find within the specified module.
 * 
 * @return The function `LM_FindSymbolAddress` is returning the address of a symbol with the given name
 * within the specified module. If the symbol is found, the address of the symbol is returned. If the
 * symbol is not found or if an error happens, `LM_ADDRESS_BAD` is returned.
 */
LM_API lm_address_t LM_CALL
LM_FindSymbolAddress(const lm_module_t *module,
		     lm_string_t        symbol_name);

/**
 * The LM_DemangleSymbol function takes a symbol name, demangles it, and returns the demangled symbol.
 * 
 * @param symbol_name The `symbol_name` parameter is a string representing the name of a symbol that
 * you want to demangle.
 * @param demangled_buf The `demangled_buf` parameter is a pointer to a buffer where the demangled
 * symbol name will be stored. If this is `NULL`, the symbol will be dynamically allocated and `maxsize`
 * is ignored.
 * @param maxsize The `maxsize` parameter in the `LM_DemangleSymbol` function represents the maximum
 * size of the buffer `demangled_buf` where the demangled symbol will be stored.
 * 
 * @return The function `LM_DemangleSymbol` returns a pointer to the demangled symbol string, or `NULL` if it
 * fails. If the symbol was dynamically allocated, you need to free it with `LM_FreeDemangledSymbol`.
 */
LM_API lm_char_t * LM_CALL
LM_DemangleSymbol(lm_string_t symbol_name,
		  lm_char_t  *demangled_buf,
		  lm_size_t   maxsize);

/**
 * The function `LM_FreeDemangledSymbol` frees the memory allocated for a demangled symbol name allocated
 * with `LM_DemangleSymbol`.
 * 
 * @param symbol_name The `symbol_name` parameter is a pointer to the string representing the name of a symbol
 * that has been demangled with `LM_DemangleSymbol` and is also dynamically allocated.
 */
LM_API lm_void_t LM_CALL
LM_FreeDemangledSymbol(lm_char_t *symbol_name);

/**
 * The function `LM_EnumSymbolsDemangled` enumerates symbols in a module with demangled names and calls
 * a provided callback function for each symbol found.
 *
 * @param module The `module` parameter is a pointer to a structure of type `lm_module_t`, which
 * represents the module where the symbols will be enumerated from.
 * @param callback The `callback` parameter in the `LM_EnumSymbols` function is a function pointer
 * that that will receive the current demangled symbol in the enumeration and an extra argument. This function
 * should return `LM_TRUE` to continue the enumeration, or `LM_FALSE` to stop it.
 * @param arg The `arg` parameter in the `LM_EnumSymbols` function is a pointer to a user-defined data
 * structure or variable that will be passed to the callback function `callback` for each symbol that
 * is enumerated. This allows the user to provide additional context or data that may be needed during
 * the symbol
 * 
 * @return The function `LM_EnumSymbols` returns `LM_TRUE` if the enumeration succeeds. Otherwise,
 * it returns `LM_FALSE`.
 */
LM_API lm_bool_t LM_CALL
LM_EnumSymbolsDemangled(const lm_module_t  *module,
			lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
						      lm_void_t   *arg),
			lm_void_t          *arg);

/**
 * The function `LM_FindSymbolAddressDemangled` searches for the address of a demangled symbol within
 * a module.
 *
 * @param module The `module` parameter is a pointer to a structure of type `lm_module_t`, which
 * represents the module where the symbol will be looked up from.
 * @param symbol_name The `symbol_name` parameter is a string representing the name of the symbol
 * (function, variable, etc) whose address you want to find within the specified module.
 * 
 * @return The function `LM_FindSymbolAddressDemangled` is returning the address of a symbol with the given
 * name within the specified module. If the symbol is found, the address of the symbol is returned. If the
 * symbol is not found or if an error happens, `LM_ADDRESS_BAD` is returned.
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
 * It allows you to provide additional information or context to the callback function when iterating over segments in a process.
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
 * It allows you to provide additional information or context to the callback function when iterating over segments in a process.
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
 * @param address The `address` parameter is of type `lm_address_t`, which is used to specify a memory
 * address to search for.
 * @param segment_out The `segment_out` parameter is a pointer to a `lm_segment_t` structure. This
 * function `LM_FindSegment` takes an address and populates the `segment_out` structure with
 * information about the segment that contains that address.
 * 
 * @return The function returns `LM_TRUE` if the enumeration was successful or `LM_FALSE` if it failed.
 */
LM_API lm_bool_t LM_CALL
LM_FindSegment(lm_address_t  address,
	       lm_segment_t *segment_out);

/**
 * The function `LM_FindSegment` searches for a memory segment that a given address is within and populates the
 * `segment_out` parameter with the result.
 * 
 * @param address The `address` parameter is of type `lm_address_t`, which is used to specify a memory
 * address to search for.
 * @param segment_out The `segment_out` parameter is a pointer to a `lm_segment_t` structure. This
 * function `LM_FindSegment` takes an address and populates the `segment_out` structure with
 * information about the segment that contains that address.
 * 
 * @return The function returns `LM_TRUE` if the enumeration was successful or `LM_FALSE` if it failed.
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
 * The function `LM_ReadMemory` reads memory from a source address and copies it to a destination
 * address.
 * 
 * @param source The `source` parameter is of type `lm_address_t`, which represents the memory address
 * from which data will be read.
 * @param dest The `dest` parameter in the `LM_ReadMemory` function is a pointer to a memory location
 * where the data read from the source address will be stored.
 * @param size The `size` parameter in the `LM_ReadMemory` function represents the number of bytes to
 * read from the memory starting at the `source` address and write into the `dest` buffer. It specifies
 * the size of the memory block to be read.
 * 
 * @return The function `LM_ReadMemory` returns the number of bytes read from memory.
 */
LM_API lm_size_t LM_CALL
LM_ReadMemory(lm_address_t source,
	      lm_byte_t   *dest,
	      lm_size_t    size);

/**
 * The function `LM_ReadMemoryEx` reads memory from a process and returns the number of bytes read.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the memory will be read from.
 * @param source The `source` parameter in the `LM_ReadMemoryEx` function represents the starting
 * address in the target process from which you want to read memory. It is of type `lm_address_t`,
 * which is a memory address in the target process's address space.
 * @param dest The `dest` parameter in the `LM_ReadMemoryEx` function is a pointer to the destination
 * buffer where the memory read operation will store the data read from the specified source address.
 * @param size The `size` parameter in the `LM_ReadMemoryEx` function represents the number of bytes to
 * read from the memory location specified by the `source` address. It indicates the amount of data
 * that should be read from the source address and copied into the destination buffer pointed to by the
 * `dest`
 * 
 * @return The function `LM_ReadMemoryEx` returns the number of bytes successfully read from the
 * specified memory address in the target process. If an error occurs during the read operation, it
 * returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_ReadMemoryEx(const lm_process_t *process,
		lm_address_t        source,
		lm_byte_t          *dest,
		lm_size_t           size);

/**
 * The LM_WriteMemory function writes data from a source array to a destination address in memory.
 * 
 * @param dest The `dest` parameter in the `LM_WriteMemory` function represents the destination memory
 * address where the data from the `source` array will be written to.
 * @param source The `source` parameter in the `LM_WriteMemory` function is used to provide the
 * data that needs to be written to the memory starting at the destination address `dest`.
 * @param size The `size` parameter in the `LM_WriteMemory` function represents the number of bytes to
 * be written from the `source` array to the memory starting at the `dest` address. It specifies the
 * size of the data to be copied from the source array to the destination memory location.
 * 
 * @return The function `LM_WriteMemory` returns the number of bytes written to the destination memory
 * address.
 */
LM_API lm_size_t LM_CALL
LM_WriteMemory(lm_address_t   dest,
	       lm_bytearray_t source,
	       lm_size_t      size);

/**
 * The function `LM_WriteMemoryEx` writes data from a source bytearray to a destination address in a
 * specified process.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the memory will be written to.
 * @param dest The `dest` parameter in the `LM_WriteMemoryEx` function represents the destination
 * address in the target process where the data from the `source` array will be written to.
 * @param source The `source` parameter in the `LM_WriteMemoryEx` is used to provide
 * the data that needs to be written to the memory of the target process.
 * @param size The `size` parameter in the `LM_WriteMemoryEx` function represents the number of bytes
 * to be written from the `source` bytearray to the memory address specified by `dest`. It indicates
 * the size of the data to be written in bytes.
 * 
 * @return The function `LM_WriteMemoryEx` returns the number of bytes that were successfully written
 * to the destination address in the process's memory. If an error occurs during the write operation,
 * it returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_WriteMemoryEx(const lm_process_t *process,
		 lm_address_t        dest,
		 lm_bytearray_t      source,
		 lm_size_t           size);

/**
 * The function `LM_SetMemory` sets a specified memory region to a given byte value.
 * 
 * @param dest The `dest` parameter is the destination memory address where the `byte` value will be
 * written to, starting from this address.
 * @param byte The `byte` parameter in the `LM_SetMemory` function represents the value of the byte
 * that will be written to the memory locations starting from the `dest` address.
 * @param size The `size` parameter in the `LM_SetMemory` function represents the number of bytes to
 * set in the memory starting from the `dest` address. It specifies the size of the memory block that
 * will be filled with the specified `byte` value.
 * 
 * @return The function `LM_SetMemory` returns the number of bytes that were successfully set to the
 * specified value `byte` in the memory region starting at address `dest`.
 */
LM_API lm_size_t LM_CALL
LM_SetMemory(lm_address_t dest,
	     lm_byte_t    byte,
	     lm_size_t    size);

/**
 * The function `LM_SetMemoryEx` sets a specified memory region to a given byte value in a target process.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the memory will be set to.
 * @param dest The `dest` parameter is the destination memory address where the `byte` value will be
 * written to, starting from this address.
 * @param byte The `byte` parameter in the `LM_SetMemoryEx` function represents the value of the byte
 * that will be written to the memory locations starting from the `dest` address.
 * @param size The `size` parameter in the `LM_SetMemoryEx` function represents the number of bytes to
 * set in the memory starting from the `dest` address. It specifies the size of the memory block that
 * will be filled with the specified `byte` value.
 * 
 * @return The function `LM_SetMemoryEx` returns a value of type `lm_size_t`, which represents the size
 * of the memory that was successfully written. If there are any errors or invalid parameters, it
 * returns `0`.
 */
LM_API lm_size_t LM_CALL
LM_SetMemoryEx(const lm_process_t *process,
	       lm_address_t        dest,
	       lm_byte_t           byte,
	       lm_size_t           size);

/**
 * The function `LM_ProtMemory` sets memory protection flags for a specified memory address range.
 * 
 * @param address The `address` parameter represents the memory address to be protected or modified.
 * @param size The `size` parameter in the `LM_ProtMemory` function represents the size of memory to be
 * protected or modified. If the `size` parameter is set to 0, the function will default to using the
 * system's page size for the operation.
 * @param prot The `prot` parameter in the `LM_ProtMemory` function represents the new protection
 * flags that you want to apply to the memory region starting at the specified address. It is of
 * type `lm_prot_t`, which is a bit mask of `LM_PROT_X` (execute), `LM_PROT_R` (read), `LM_PROT_W` (write).
 * @param oldprot_out The `oldprot_out` parameter in the `LM_ProtMemory` function is a pointer to a
 * `lm_prot_t` type variable. This parameter is used to store the old protection flags of a memory
 * segment before they are updated with the new protection settings specified by the `prot` parameter.
 * 
 * @return The function `LM_ProtMemory` returns a boolean value, either `LM_TRUE` or `LM_FALSE`, based
 * on the success of the memory protection operation.
 */
LM_API lm_bool_t LM_CALL
LM_ProtMemory(lm_address_t address,
	      lm_size_t    size,
	      lm_prot_t    prot,
	      lm_prot_t   *oldprot_out);

/**
 * The function `LM_ProtMemoryEx` is used to modify memory protection flags for a specified address
 * range in a given process.
 *
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the memory flags will be modified from.
 * @param address The `address` parameter represents the memory address to be protected or modified.
 * @param size The `size` parameter in the `LM_ProtMemoryEx` function represents the size of memory to be
 * protected or modified. If the `size` parameter is set to 0, the function will default to using the
 * system's page size for the operation.
 * @param prot The `prot` parameter in the `LM_ProtMemoryEx` function represents the new protection
 * flags that you want to apply to the memory region starting at the specified address. It is of
 * type `lm_prot_t`, which is a bit mask of `LM_PROT_X` (execute), `LM_PROT_R` (read), `LM_PROT_W` (write).
 * @param oldprot_out The `oldprot_out` parameter in the `LM_ProtMemoryEx` function is a pointer to a
 * `lm_prot_t` type variable. This parameter is used to store the old protection flags of a memory
 * segment before they are updated with the new protection settings specified by the `prot` parameter.
 *
 * @return The function `LM_ProtMemoryEx` returns a boolean value indicating whether the memory
 * protection operation was successful or not. It returns `LM_TRUE` if the operation was successful and
 * `LM_FALSE` if it was not.
 */
LM_API lm_bool_t LM_CALL
LM_ProtMemoryEx(const lm_process_t *process,
		lm_address_t        address,
		lm_size_t           size,
		lm_prot_t           prot,
		lm_prot_t          *oldprot_out);

/**
 * The function `LM_AllocMemory` allocates memory with a specified size and protection flags, returning
 * the allocated memory address.
 * 
 * @param size The `size` parameter in the `LM_AllocMemory` function represents the size of memory to
 * be allocated. If the `size` is 0, the function will allocate a full page of memory. If a specific
 * size is provided, that amount of memory will be allocated, aligned to the next page size.
 * @param prot The `prot` parameter in the `LM_AllocMemory` function specifies the memory protection
 * flags for the allocated memory region. It is of type `lm_prot_t`, which is an enum that represents
 * different memory protection flags such as read (`LM_PROT_R`), write (`LM_PROT_W`), execute (`LM_PROT_X`)
 * permissions.
 * 
 * @return The function `LM_AllocMemory` returns the memory address of the allocated memory with the specified
 * allocation options, or `LM_ADDRESS_BAD` if it fails.
 */
LM_API lm_address_t LM_CALL
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot);

/**
 * The function `LM_AllocMemoryEx` allocates memory in a specified process with the given size and
 * memory protection flags.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the memory will be allocated to.
 * @param size The `size` parameter in the `LM_AllocMemory` function represents the size of memory to
 * be allocated. If the `size` is 0, the function will allocate a full page of memory. If a specific
 * size is provided, that amount of memory will be allocated, aligned to the next page size.
 * @param prot The `prot` parameter in the `LM_AllocMemory` function specifies the memory protection
 * flags for the allocated memory region. It is of type `lm_prot_t`, which is an enum that represents
 * different memory protection flags such as read (`LM_PROT_R`), write (`LM_PROT_W`), execute (`LM_PROT_X`)
 * permissions.
 * 
 * @return The function `LM_AllocMemoryEx` returns a memory address of type `lm_address_t` if the
 * memory allocation is successful. If there are any issues, it returns `LM_ADDRESS_BAD`.
 */
LM_API lm_address_t LM_CALL
LM_AllocMemoryEx(const lm_process_t *process,
		 lm_size_t           size,
		 lm_prot_t           prot);

/**
 * The function `LM_FreeMemory` deallocates memory that was previously allocated with `LM_AllocMemory`.
 * 
 * @param alloc The `alloc` parameter is the address of the memory block that was previously allocated.
 * @param size The `size` parameter represents the size of the memory block that was previously
 * allocated. If the size is 0, the function will use the system's page size for unmapping the memory.
 * 
 * @return The function `LM_FreeMemory` returns `LM_TRUE` if the memory deallocation operation is
 * successful, and `LM_FALSE` if the operation fails.
 */
LM_API lm_bool_t LM_CALL
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size);

/**
 * The function `LM_FreeMemoryEx` deallocates memory that was previously allocated with `LM_AllocMemoryEx`
 * on a given process.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the memory will be allocated to.
 * @param alloc The `alloc` parameter in the `LM_FreeMemoryEx` function represents the address of the
 * memory block that was previously allocated and needs to be freed.
 * @param size The `size` parameter in the `LM_FreeMemoryEx` function represents the size of the memory
 * block that was previously allocated and now needs to be freed. If the `size` parameter is set to 0,
 * the function will use the system's page size as the default size for freeing the memory.
 * 
 * @return The function `LM_FreeMemoryEx` returns a boolean value (`LM_TRUE` or `LM_FALSE`) indicating
 * whether the memory deallocation operation was successful or not.
 */
LM_API lm_bool_t LM_CALL
LM_FreeMemoryEx(const lm_process_t *process,
		lm_address_t        alloc,
		lm_size_t           size);

/**
 * The function `LM_DeepPointer` calculates a deep pointer address by applying a series of offsets to a
 * base address and dereferencing intermediate pointers.
 * 
 * @param base The `base` parameter in the `LM_DeepPointer` function represents the starting address
 * from which to calculate the deep pointer.
 * @param offsets The `offsets` parameter is a pointer to an array of lm_address_t values. These values
 * are used as offsets to navigate through memory addresses in the `LM_DeepPointer` function.
 * @param noffsets The `noffsets` parameter in the `LM_DeepPointer` function represents the number of
 * offsets in the `offsets` array. It indicates how many elements are in the array that contains the
 * offsets used to calculate the final memory address.
 * 
 * @return The function `LM_DeepPointer` returns a deep pointer calculated based on the provided base
 * address, offsets, and number of offsets. The function iterates through the offsets, adjusting the
 * base address and dereferencing accordingly.
 */
LM_API lm_address_t LM_CALL
LM_DeepPointer(lm_address_t        base,
	       const lm_address_t *offsets,
	       size_t              noffsets);

/**
 * The function `LM_DeepPointerEx` calculates a deep pointer address by applying a series of offsets to a
 * base address and dereferencing intermediate pointers in a given process's memory space.
 *
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process that the deep pointer will be calculated from.
 * @param base The `base` parameter in the `LM_DeepPointerEx` function represents the starting address
 * from which to calculate the deep pointer.
 * @param offsets The `offsets` parameter is a pointer to an array of lm_address_t values. These values
 * are used as offsets to navigate through memory addresses in the `LM_DeepPointerEx` function.
 * @param noffsets The `noffsets` parameter in the `LM_DeepPointerEx` function represents the number of
 * offsets in the `offsets` array. It indicates how many elements are in the array that contains the
 * offsets used to calculate the final memory address.
 * 
 * @return The function `LM_DeepPointerEx` returns a deep pointer calculated based on the provided base
 * address, offsets, and number of offsets. The function iterates through the offsets, adjusting the
 * base address and dereferencing accordingly.
 */
LM_API lm_address_t LM_CALL
LM_DeepPointerEx(const lm_process_t *process,
		 lm_address_t        base,
		 const lm_address_t *offsets,
		 lm_size_t           noffsets);

/* Scan API */

/**
 * The function `LM_DataScan` scans a specified memory address range for a specific data pattern and
 * returns the address where the pattern is found.
 * 
 * @param data The `data` parameter is a byte array containing the data to be scanned for in memory.
 * @param datasize The `datasize` parameter in the `LM_DataScan` function represents the size of the
 * data array that you are searching for within the memory range specified by `address` and `scansize`.
 * It indicates the number of bytes that need to match consecutively in order to consider it a match.
 * @param address The `address` parameter in the `LM_DataScan` function represents the starting memory
 * address where the scanning operation will begin. The function will scan a range of memory starting
 * from this address to find the data.
 * @param scansize The `scansize` parameter in the `LM_DataScan` function represents the size of the
 * memory region to scan starting from the specified `address`. It determines the range within which
 * the function will search for a match with the provided `data` array.
 * 
 * @return The function `LM_DataScan` returns an `lm_address_t` value, which represents the memory
 * address where a match for the provided data was found. If no match is found, it returns the value
 * `LM_ADDRESS_BAD`.
 */
LM_API lm_address_t LM_CALL
LM_DataScan(lm_bytearray_t data,
	    lm_size_t      datasize,
	    lm_address_t   address,
	    lm_size_t      scansize);

/**
 * The function `LM_DataScanEx` scans a specified memory address range for a specific data pattern in a
 * given process and returns the address where the pattern is found.
 * 
 * @param process The `process` parameter is a pointer to a structure representing a process in the
 * system. It's the process whose memory will be scanned.
 * @param data The `data` parameter is a byte array containing the data to be scanned for in memory.
 * @param datasize The `datasize` parameter in the `LM_DataScanEx` function represents the size of the
 * data array that you are searching for within the memory range specified by `address` and `scansize`.
 * It indicates the number of bytes that need to match consecutively in order to consider it a match.
 * @param address The `address` parameter in the `LM_DataScanEx` function represents the starting memory
 * address where the scanning operation will begin. The function will scan a range of memory starting
 * from this address to find the data.
 * @param scansize The `scansize` parameter in the `LM_DataScanEx` function represents the size of the
 * memory region to scan starting from the specified `address`. It determines the range within which
 * the function will search for a match with the provided `data` array.
 * 
 * @return The function `LM_DataScanEx` returns an `lm_address_t` value, which represents the memory
 * address where a match for the provided data was found. If no match is found, it returns the value
 * `LM_ADDRESS_BAD`.
 */
LM_API lm_address_t LM_CALL
LM_DataScanEx(const lm_process_t *process,
	      lm_bytearray_t      data,
	      lm_size_t           datasize,
	      lm_address_t        address,
	      lm_size_t           scansize);

/**
 * The function `LM_PatternScan` function searches for a specific pattern in memory based on a given mask.
 * 
 * @param pattern The `pattern` parameter is an array of bytes that represents the pattern you are
 * searching for in memory.
 * @param mask The `mask` parameter in the `LM_PatternScan` function is a string that represents the
 * pattern mask used for scanning memory. It is used to specify which bytes in the pattern should be
 * matched against the memory content. The mask can contain characters such as '?' which act as
 * wildcards, allowing any byte to be matched. You can also use 'x' to have an exact match.
 * @param address The `address` parameter in the `LM_PatternScan` function represents the starting
 * address in memory where the pattern scanning will begin. The function will scan the memory starting
 * from this address to find the pattern match.
 * @param scansize The `scansize` parameter in the `LM_PatternScan` function represents the size of the
 * memory region to scan starting from the specified `address`. It determines the range within which
 * the function will search for the specified pattern based on the provided `pattern` and `mask`.
 * 
 * @return The function `LM_PatternScan` returns an `lm_address_t` value, which represents the memory
 * address where a match for the given pattern and mask is found within the specified scan size
 * starting from the provided address. If no match is found or if an error occurs, the
 * function returns `LM_ADDRESS_BAD`.
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
LM_API lm_arch_t LM_CALL
LM_GetArchitecture();

LM_API lm_bool_t LM_CALL
LM_Assemble(lm_string_t code,
	    lm_inst_t  *instruction_out);

LM_API lm_size_t LM_CALL
LM_AssembleEx(lm_string_t  code,
              lm_arch_t    arch,
	      lm_size_t    bits,
	      lm_address_t runtime_address,
	      lm_byte_t  **payload_out);

LM_API lm_void_t LM_CALL
LM_FreePayload(lm_byte_t *payload);

LM_API lm_bool_t LM_CALL
LM_Disassemble(lm_address_t machine_code,
	       lm_inst_t   *instruction_out);

LM_API lm_size_t LM_CALL
LM_DisassembleEx(lm_address_t machine_code,
                 lm_arch_t    arch,
		 lm_size_t    bits,
		 lm_size_t    max_size,
		 lm_size_t    instruction_count,
		 lm_address_t runtime_address,
		 lm_inst_t  **instructions_out);

LM_API lm_void_t LM_CALL
LM_FreeInstructions(lm_inst_t *instructions);

LM_API lm_size_t LM_CALL
LM_CodeLength(lm_address_t machine_code,
	      lm_size_t    min_length);

LM_API lm_size_t LM_CALL
LM_CodeLengthEx(const lm_process_t *process,
		lm_address_t        machine_code,
		lm_size_t           min_length);

/* Hook API */
LM_API lm_size_t LM_CALL
LM_HookCode(lm_address_t  from,
	    lm_address_t  to,
	    lm_address_t *trampoline_out);

LM_API lm_size_t LM_CALL
LM_HookCodeEx(const lm_process_t *process,
	      lm_address_t        from,
	      lm_address_t        to,
	      lm_address_t       *trampoline_out);

LM_API lm_bool_t LM_CALL
LM_UnhookCode(lm_address_t from,
	      lm_address_t trampoline,
	      lm_size_t    size);

LM_API lm_bool_t LM_CALL
LM_UnhookCodeEx(const lm_process_t *process,
		lm_address_t        from,
		lm_address_t        trampoline,
		lm_size_t           size);

/* Virtual Method Table API */
LM_API lm_bool_t LM_CALL
LM_VmtNew(lm_address_t *vtable,
	  lm_vmt_t     *vmt_out);

LM_API lm_bool_t LM_CALL
LM_VmtHook(lm_vmt_t    *vmt,
	   lm_size_t    from_fn_index,
	   lm_address_t to);

LM_API lm_void_t LM_CALL
LM_VmtUnhook(lm_vmt_t *vmt,
	     lm_size_t fn_index);

LM_API lm_address_t LM_CALL
LM_VmtGetOriginal(const lm_vmt_t *vmt,
		  lm_size_t       fn_index);

LM_API lm_void_t LM_CALL
LM_VmtReset(lm_vmt_t *vmt);

LM_API lm_void_t LM_CALL
LM_VmtFree(lm_vmt_t *vmt);

#ifdef __cplusplus
}
#endif

#endif
