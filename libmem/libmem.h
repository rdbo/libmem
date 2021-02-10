/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |  https://github.com/rdbo/libmem  |
 *  ----------------------------------
 */

#pragma once
#ifndef LIBMEM_H
#define LIBMEM_H

//Operating System
#define MEM_WIN   0
#define MEM_LINUX 1

#if (defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__) && !defined(linux)) || (defined(MEM_FORCE_WIN) && !defined(MEM_FORCE_LINUX))
#define MEM_OS MEM_WIN
#elif (defined(linux) || defined(__linux__)) || defined(MEM_FORCE_LINUX)
#define MEM_OS MEM_LINUX
#endif

//Architecture
#define _MEM_ARCH_x86_32  0
#define _MEM_ARCH_x86_64  1
#define _MEM_ARCH_UNKNOWN 2

#if (defined(_M_X64) || defined(__LP64__) || defined(_LP64) || defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64))
#define MEM_ARCH _MEM_ARCH_x86_64
#elif (defined(_M_IX86) || defined(__i386__) || (defined(__WORDSIZE) && __WORDSIZE == 32))
#define MEM_ARCH _MEM_ARCH_x86_32
#else
#define MEM_ARCH _MEM_ARCH_UNKNOWN
#endif

//Charset
#define MEM_UCS  0
#define MEM_MBCS 1

#if defined(_UNICODE) && defined(MEM_WIN)
#define MEM_CHARSET MEM_UCS
#else
#define MEM_CHARSET MEM_MBCS
#endif

//Language
#if defined(__cplusplus)
#define MEM_CPP
#else
#define MEM_C
#endif

//Compatibility
#if defined(MEM_OS) && defined(MEM_ARCH)
#define MEM_COMPATIBLE
#endif

//Helpers
#define PAD_STR __pad
#define CONCAT_STR(str1, str2) str1##str2
#define _MERGE_STR (str1, str2) str1 str2
#define MERGE_STR (str1, str2) _MERGE_STR(str1, str2)
#define _STRINGIFY(str) #str
#define STRINGIFY (str) _STRINGIFY(str)
#define NEW_PAD(size) CONCAT_STR(PAD_STR, __COUNTER__)[size]
#define UNION_MEMBER(type, varname, offset) struct { unsigned char NEW_PAD(offset); type varname; }
#define UNION_MEMBER_BUF(type, varname, size, offset) struct { unsigned char NEW_PAD(offset); type varname[size]; }
#if   MEM_CHARSET == MEM_UCS
#define MEM_STR(str) CONCAT_STR(L, str)
#define MEM_STR_CMP(str1, str2) wcscmp(str1, str2)
#define MEM_STR_N_CMP(str1, str2, n) wcsncmp(str1, str2, n)
#define MEM_STR_LEN(str) wcslen(str)
#define MEM_STR_CHR(str, c) wcschr(str, c)
#define MEM_STR_STR(str, sstr) wcsstr(str, sstr)
#elif MEM_CHARSET == MEM_MBCS
#define MEM_STR(str) str
#define MEM_STR_CMP(str1, str2) strcmp(str1, str2)
#define MEM_STR_N_CMP(str1, str2, n) strncmp(str1, str2, n)
#define MEM_STR_LEN(str) strlen(str)
#define MEM_STR_CHR(str, c) strchr(str, c)
#define MEM_STR_STR(str, sstr) strstr(str, sstr)
#endif

//Other
#define MEM_NULL 0
#define MEM_BAD  -1
#define MEM_GOOD !MEM_BAD
#if   MEM_OS == MEM_WIN
#define MEM_PATH_MAX MAX_PATH
#elif MEM_OS == MEM_LINUX
#define MEM_PATH_MAX PATH_MAX
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

#ifdef MEM_COMPATIBLE

//Includes
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#if   MEM_OS == MEM_WIN
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#elif MEM_OS == MEM_LINUX
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/io.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#endif //MEM_OS

#ifdef MEM_CPP
extern "C"
{
#endif

//Types
typedef enum { MEM_FALSE = 0, MEM_TRUE = 1 } mem_bool_t;
typedef int                                  mem_int_t;
typedef void                                 mem_void_t;

typedef int8_t                               mem_int8_t;
typedef int16_t                              mem_int16_t;
typedef int32_t                              mem_int32_t;
typedef int64_t                              mem_int64_t;

typedef uint8_t                              mem_uint8_t;
typedef uint16_t                             mem_uint16_t;
typedef uint32_t                             mem_uint32_t;
typedef uint64_t                             mem_uint64_t;

typedef intptr_t                             mem_intptr_t;
typedef uintptr_t                            mem_uintptr_t;

typedef mem_uint8_t                          mem_byte_t;
typedef mem_uint16_t                         mem_word_t;
typedef mem_uint32_t                         mem_dword_t;
typedef mem_uint64_t                         mem_qword_t;

typedef size_t                               mem_size_t;

typedef wchar_t                              mem_wchar_t;
typedef char                                 mem_char_t;

#if   MEM_CHARSET == MEM_UCS
typedef mem_wchar_t                          mem_tchar_t;
#elif MEM_CHARSET == MEM_MBCS
typedef mem_char_t                           mem_tchar_t;
#endif

typedef mem_char_t                          *mem_cstring_t;
typedef mem_wchar_t                         *mem_wstring_t;
typedef mem_tchar_t                         *mem_tstring_t;
#ifndef MEM_CPP
typedef mem_tstring_t                        mem_string_t;
#endif
typedef mem_byte_t                          *mem_data_t;
typedef mem_void_t                          *mem_voidptr_t;

#if   MEM_OS == MEM_WIN
typedef DWORD                                mem_pid_t;
typedef DWORD                                mem_prot_t;
typedef DWORD                                mem_flags_t;
#elif MEM_OS == MEM_LINUX
typedef mem_int32_t                          mem_pid_t;
typedef mem_int32_t                          mem_prot_t;
typedef mem_int32_t                          mem_flags_t;
#endif

typedef enum
{
	MEM_ARCH_x86_32  = _MEM_ARCH_x86_32,
	MEM_ARCH_x86_64  = _MEM_ARCH_x86_64,
	MEM_ARCH_UNKNOWN = _MEM_ARCH_UNKNOWN
} mem_arch_t;

typedef enum
{
	MEM_ASM_x86_JMP32 = 0,
	/*
	 * jmp REL_ADDR
	 */

	MEM_ASM_x86_JMP64,
	/*
	 * mov eax, ABS_ADDR
	 * jmp eax
	 */

	MEM_ASM_x86_CALL32,
	/*
	 * call REL_ADDR
	 */

	MEM_ASM_x86_CALL64,
	/*
	 * mov eax, ABS_ADDR
	 * call eax
	 */

	MEM_ASM_DETOUR_INVALID,

	MEM_ASM_x86_SYSCALL32,

	/*
	 * int80
	 */

	MEM_ASM_x86_SYSCALL64,

	/*
	 * syscall
	 */

	MEM_ASM_x86_LIBCALL32_1, //x86_32 Library Call with 1 parameter
	/*
	 * push ebx
	 * call eax //call dlclose
	 * int3
	 */

	MEM_ASM_x86_LIBCALL32_2, //x86_32 Library Call with 2 parameters
	/*
	 * push ecx
	 * push ebx
	 * call eax //call dlopen
	 * int3
	 */

	MEM_ASM_x86_LIBCALL64, //x86_64 Library Call
	/*
	 * call rax //call dlopen
	 * int3
	 */

	MEM_ASM_INVALID
} mem_asm_t;

typedef enum
{
	LoadFile = 0,
	LoadMemory,
	LoadInvalid
} mem_load_t;

typedef struct
{
	mem_data_t payload;
	mem_size_t size;
} mem_payload_t;

typedef struct
{
	mem_pid_t  pid;
	mem_arch_t arch;
} mem_process_t;

typedef struct
{
	mem_voidptr_t base;
	mem_uintptr_t size;
	mem_voidptr_t end;
} mem_module_t;

typedef struct
{
	mem_voidptr_t base;
	mem_uintptr_t size;
	mem_voidptr_t end;
	mem_flags_t   flags;
	mem_prot_t    protection;
} mem_page_t;

//Functions
//mem_in
mem_pid_t          mem_in_get_pid(mem_void_t);
mem_size_t         mem_in_get_process_name(mem_tstring_t *pprocess_name);
mem_size_t         mem_in_get_process_path(mem_tstring_t *pprocess_path);
mem_arch_t         mem_in_get_arch(mem_void_t);
mem_process_t      mem_in_get_process(mem_void_t);
mem_module_t       mem_in_get_module(mem_tstring_t module_ref);
mem_size_t         mem_in_get_module_name(mem_module_t mod, mem_tstring_t *pmodule_name);
mem_size_t         mem_in_get_module_path(mem_module_t mod, mem_tstring_t *pmodule_path);
mem_size_t         mem_in_get_module_list(mem_module_t **pmodule_list);
mem_page_t         mem_in_get_page(mem_voidptr_t src);
mem_bool_t         mem_in_read(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size);
mem_bool_t         mem_in_write(mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size);
mem_bool_t         mem_in_set(mem_voidptr_t src, mem_byte_t byte, mem_size_t size);
mem_voidptr_t      mem_in_syscall(mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5);
mem_bool_t         mem_in_protect(mem_voidptr_t src, mem_size_t size, mem_prot_t protection, mem_prot_t *pold_protection);
mem_voidptr_t      mem_in_allocate(mem_size_t size, mem_prot_t protection);
mem_bool_t         mem_in_deallocate(mem_voidptr_t src, mem_size_t size);
mem_voidptr_t      mem_in_scan(mem_data_t data, mem_size_t size, mem_voidptr_t start, mem_voidptr_t stop);
mem_voidptr_t      mem_in_pattern_scan(mem_data_t pattern, mem_tstring_t mask, mem_voidptr_t start, mem_voidptr_t stop);
mem_size_t         mem_in_detour_size(mem_asm_t method);
mem_size_t         mem_in_payload_size(mem_asm_t method);
mem_bool_t         mem_in_detour(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_asm_t method, mem_data_t *stolen_bytes);
mem_voidptr_t      mem_in_detour_trampoline(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_asm_t method, mem_data_t *stolen_bytes);
mem_bool_t         mem_in_detour_restore(mem_voidptr_t src, mem_data_t stolen_bytes, mem_size_t size);
mem_module_t       mem_in_load_module(mem_tstring_t path);
mem_bool_t         mem_in_unload_module(mem_module_t mod);
mem_voidptr_t      mem_in_get_symbol(mem_module_t mod, mem_cstring_t symbol);
//mem_ex
mem_pid_t          mem_ex_get_pid(mem_tstring_t process_ref);
mem_size_t         mem_ex_get_process_name(mem_pid_t pid, mem_tstring_t *pprocess_name);
mem_size_t         mem_ex_get_process_path(mem_pid_t pid, mem_tstring_t *pprocess_path);
mem_arch_t         mem_ex_get_system_arch(mem_void_t);
mem_arch_t         mem_ex_get_arch(mem_pid_t pid);
mem_process_t      mem_ex_get_process(mem_pid_t pid);
mem_size_t         mem_ex_get_process_list(mem_process_t **pprocess_list);
mem_module_t       mem_ex_get_module(mem_process_t process, mem_tstring_t module_ref);
mem_size_t         mem_ex_get_module_name(mem_process_t process, mem_module_t mod, mem_tstring_t *pmodule_name);
mem_size_t         mem_ex_get_module_path(mem_process_t process, mem_module_t mod, mem_tstring_t *pmodule_path);
mem_size_t         mem_ex_get_module_list(mem_process_t process, mem_module_t **pmodule_list);
mem_page_t         mem_ex_get_page(mem_process_t process, mem_voidptr_t src);
mem_bool_t         mem_ex_is_process_running(mem_process_t process);
mem_bool_t         mem_ex_read(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size);
mem_bool_t         mem_ex_write(mem_process_t process, mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size);
mem_bool_t         mem_ex_set(mem_process_t process, mem_voidptr_t dst, mem_byte_t byte, mem_size_t size);
mem_voidptr_t      mem_ex_syscall(mem_process_t process, mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5);
mem_bool_t         mem_ex_protect(mem_process_t process, mem_voidptr_t src, mem_size_t size, mem_prot_t protection, mem_prot_t *pold_protection);
mem_voidptr_t      mem_ex_allocate(mem_process_t process, mem_size_t size, mem_prot_t protection);
mem_bool_t         mem_ex_deallocate(mem_process_t process, mem_voidptr_t src, mem_size_t size);
mem_voidptr_t      mem_ex_scan(mem_process_t process, mem_data_t data, mem_size_t size, mem_voidptr_t start, mem_voidptr_t stop);
mem_voidptr_t      mem_ex_pattern_scan(mem_process_t process, mem_data_t pattern, mem_tstring_t mask, mem_voidptr_t start, mem_voidptr_t stop);
mem_module_t       mem_ex_load_module(mem_process_t process, mem_tstring_t path);
mem_bool_t         mem_ex_unload_module(mem_process_t process, mem_module_t mod);
mem_voidptr_t      mem_ex_get_symbol(mem_process_t process, mem_module_t mod, mem_cstring_t symbol);

#ifdef MEM_CPP
}
#endif

#endif //MEM_COMPATIBLE
#endif //LIBMEM_H
