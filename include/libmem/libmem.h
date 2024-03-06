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
typedef uint8_t  lm_byte_t;
typedef uint64_t lm_address_t;
typedef uint64_t lm_size_t;

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

	LM_PROT_X = (1 << 0),
	LM_PROT_R = (1 << 1),
	LM_PROT_W = (1 << 2),

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

typedef struct {
	lm_address_t base;
	lm_address_t end;
	lm_size_t    size;
	lm_prot_t    prot;
} lm_page_t;

typedef struct {
	lm_string_t  name;
	lm_address_t address;
} lm_symbol_t;

/* Similar to capstone's cs_insn */
typedef struct {
	lm_address_t address;
	lm_size_t    size;
	lm_byte_t    bytes[LM_INST_MAX];
	lm_char_t    mnemonic[32];
	lm_char_t    op_str[160];
} lm_inst_t;

/* Virtual method table (VMT) */
typedef struct lm_vmtentry_t {
	lm_address_t          orig_func;
	lm_size_t             index;
	struct lm_vmtentry_t *next;
} lm_vmtentry_t;

typedef struct {
	lm_prot_t      orig_prot;
	lm_address_t  *vtable;
	lm_vmtentry_t *entries;
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
LM_API lm_bool_t LM_CALL
LM_EnumProcesses(lm_bool_t (LM_CALL *callback)(lm_process_t *process,
					       lm_void_t    *arg),
		 lm_void_t          *arg);

LM_API lm_bool_t LM_CALL
LM_GetProcess(lm_process_t *process_out);

LM_API lm_bool_t LM_CALL
LM_GetProcessEx(lm_pid_t      pid,
		lm_process_t *process_out);

LM_API lm_bool_t LM_CALL
LM_FindProcess(lm_string_t   process_name,
	       lm_process_t *process_out);

LM_API lm_bool_t LM_CALL
LM_IsProcessAlive(const lm_process_t *process);

LM_API lm_size_t LM_CALL
LM_GetSystemBits(lm_void_t);

/* Thread API */
LM_API lm_bool_t LM_CALL
LM_EnumThreads(lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

LM_API lm_bool_t LM_CALL
LM_EnumThreadsEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_thread_t *thread,
					       lm_void_t   *arg),
		 lm_void_t          *arg);

LM_API lm_bool_t LM_CALL
LM_GetThread(lm_thread_t *thread_out);

LM_API lm_bool_t LM_CALL
LM_GetThreadEx(const lm_process_t *process,
	       lm_thread_t        *thread_out);

LM_API lm_bool_t LM_CALL
LM_GetThreadProcess(const lm_thread_t *thread,
		    lm_process_t      *process_out);

/* Module API */
LM_API lm_bool_t LM_CALL
LM_EnumModules(lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					       lm_void_t   *arg),
		 lm_void_t          *arg);

LM_API lm_bool_t LM_CALL
LM_FindModule(lm_string_t  name,
	      lm_module_t *module_out);

LM_API lm_bool_t LM_CALL
LM_FindModuleEx(const lm_process_t *process,
		lm_string_t         name,
		lm_module_t        *module_out);

LM_API lm_bool_t LM_CALL
LM_LoadModule(lm_string_t  path,
	      lm_module_t *module_out);

LM_API lm_bool_t LM_CALL
LM_LoadModuleEx(const lm_process_t *process,
		lm_string_t         path,
		lm_module_t        *module_out);

LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module);

LM_API lm_bool_t LM_CALL
LM_UnloadModuleEx(const lm_process_t *process,
		  const lm_module_t  *module);

/* Symbol API */
LM_API lm_bool_t LM_CALL
LM_EnumSymbols(const lm_module_t  *module,
	       lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
					     lm_void_t   *arg),
	       lm_void_t          *arg);

LM_API lm_address_t LM_CALL
LM_FindSymbolAddress(const lm_module_t *module,
		     lm_string_t        symbol_name);

LM_API lm_char_t * LM_CALL
LM_DemangleSymbol(lm_string_t symbol_name,
		  lm_char_t  *demangled_buf,
		  lm_size_t   maxsize);

LM_API lm_void_t LM_CALL
LM_FreeDemangledSymbol(lm_char_t *symbol_name);

LM_API lm_bool_t LM_CALL
LM_EnumSymbolsDemangled(const lm_module_t  *module,
			lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
						      lm_void_t   *arg),
			lm_void_t          *arg);

LM_API lm_address_t
LM_FindSymbolAddressDemangled(const lm_module_t *module,
			      lm_string_t        symbol_name);

/* Memory API */
LM_API lm_size_t LM_CALL
LM_ReadMemory(lm_address_t source,
	      lm_byte_t   *dest,
	      lm_size_t    size);

LM_API lm_size_t LM_CALL
LM_ReadMemoryEx(const lm_process_t *process,
		lm_address_t        source,
		lm_byte_t          *dest,
		lm_size_t           size);

LM_API lm_size_t LM_CALL
LM_WriteMemory(lm_address_t   dest,
	       lm_bytearray_t source,
	       lm_size_t      size);

LM_API lm_size_t LM_CALL
LM_WriteMemoryEx(const lm_process_t *process,
		 lm_address_t        dest,
		 lm_bytearray_t      source,
		 lm_size_t           size);

LM_API lm_size_t LM_CALL
LM_SetMemory(lm_address_t dest,
	     lm_byte_t    byte,
	     lm_size_t    size);

LM_API lm_size_t LM_CALL
LM_SetMemoryEx(const lm_process_t *process,
	       lm_address_t        dest,
	       lm_byte_t           byte,
	       lm_size_t           size);

LM_API lm_bool_t LM_CALL
LM_ProtMemory(lm_address_t address,
	      lm_size_t    size,
	      lm_prot_t    prot,
	      lm_prot_t   *oldprot);

LM_API lm_bool_t LM_CALL
LM_ProtMemoryEx(const lm_process_t *process,
		lm_address_t        address,
		lm_size_t           size,
		lm_prot_t           prot,
		lm_prot_t          *oldprot);

LM_API lm_address_t LM_CALL
LM_AllocMemory(lm_size_t size,
	       lm_prot_t prot);

LM_API lm_address_t LM_CALL
LM_AllocMemoryEx(const lm_process_t *process,
		 lm_size_t           size,
		 lm_prot_t           prot);

LM_API lm_bool_t LM_CALL
LM_FreeMemory(lm_address_t alloc,
	      lm_size_t    size);

LM_API lm_bool_t LM_CALL
LM_FreeMemoryEx(const lm_process_t *process,
		lm_address_t        alloc,
		lm_size_t           size);

LM_API lm_address_t LM_CALL
LM_DeepPointer(lm_address_t        base,
	       const lm_address_t *offsets,
	       size_t              noffsets);

LM_API lm_address_t LM_CALL
LM_DeepPointerEx(const lm_process_t *process,
		 lm_address_t        base,
		 const lm_address_t *offsets,
		 lm_size_t           noffsets);

#ifdef __cplusplus
}
#endif

#endif
