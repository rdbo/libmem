//Made by rdbo
//https://github.com/rdbo/libmem
//C-compatible version of https://github.com/rdbo/Memory

#pragma once
#ifndef MEM
#define MEM

//Operating System

#if (defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__) && !defined(linux)) || (defined(MEM_FORCE_WIN) && !defined(MEM_FORCE_LINUX))
#define MEM_WIN
#elif (defined(linux) || defined(__linux__)) || defined(MEM_FORCE_LINUX)
#define MEM_LINUX
#endif

//Architecture

#if (defined(_M_IX86) || defined(__i386__) || __WORDSIZE == 32) || (defined(MEM_FORCE_86) && !defined(MEM_FORCE_64))
#define MEM_86
#elif (defined(_M_X64) || defined(__LP64__) || defined(_LP64) || __WORDSIZE == 64) || defined(MEM_FORCE_64)
#define MEM_64
#endif

//Charset

#if defined(_UNICODE) && defined(MEM_WIN)
#define MEM_UCS
#else
#define MEM_MBCS
#endif

//Functions

#if defined(_MSC_VER)
#define PP_NARG(...) _COUNTOF_CAT( _COUNTOF_A, ( 0, ##__VA_ARGS__, 100,\
    99, 98, 97, 96, 95, 94, 93, 92, 91, 90,\
    89, 88, 87, 86, 85, 84, 83, 82, 81, 80,\
    79, 78, 77, 76, 75, 74, 73, 72, 71, 70,\
    69, 68, 67, 66, 65, 64, 63, 62, 61, 60,\
    59, 58, 57, 56, 55, 54, 53, 52, 51, 50,\
    49, 48, 47, 46, 45, 44, 43, 42, 41, 40,\
    39, 38, 37, 36, 35, 34, 33, 32, 31, 30,\
    29, 28, 27, 26, 25, 24, 23, 22, 21, 20,\
    19, 18, 17, 16, 15, 14, 13, 12, 11, 10,\
    9, 8, 7, 6, 5, 4, 3, 2, 1, 0 ) )
#define _COUNTOF_CAT( a, b ) a b
#define _COUNTOF_A( a0, a1, a2, a3, a4, a5, a6, a7, a8, a9,\
    a10, a11, a12, a13, a14, a15, a16, a17, a18, a19,\
    a20, a21, a22, a23, a24, a25, a26, a27, a28, a29,\
    a30, a31, a32, a33, a34, a35, a36, a37, a38, a39,\
    a40, a41, a42, a43, a44, a45, a46, a47, a48, a49,\
    a50, a51, a52, a53, a54, a55, a56, a57, a58, a59,\
    a60, a61, a62, a63, a64, a65, a66, a67, a68, a69,\
    a70, a71, a72, a73, a74, a75, a76, a77, a78, a79,\
    a80, a81, a82, a83, a84, a85, a86, a87, a88, a89,\
    a90, a91, a92, a93, a94, a95, a96, a97, a98, a99,\
    a100, n, ... ) n
#else
#define PP_NARG(...) \
         PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...) \
         PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,N,...) N
#define PP_RSEQ_N() \
         63,62,61,60,                   \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0
#endif

#define PAD_STR __pad
#define _CONCAT_STR(a, b) a##b
#define CONCAT_STR(a, b) _CONCAT_STR(a, b)
#define _MERGE_STR(a, b) a b
#define MERGE_STR(a, b) _MERGE_STR(a, b)
#define NEW_PAD(size) CONCAT_STR(PAD_STR, __COUNTER__)[size]
#define CREATE_UNION_MEMBER(type, varname, offset) struct { unsigned char NEW_PAD(offset); type varname; } //Create relative offset variable from union
#define _BUFFER_GENERATE(...) { __VA_ARGS__ }
#define ASM_GENERATE(...) _BUFFER_GENERATE(__VA_ARGS__)
#define _CALC_ARG_LENGTH(...) PP_NARG(__VA_ARGS__)
#define CALC_ARG_LENGTH(...) _CALC_ARG_LENGTH(__VA_ARGS__)
#define CALC_ASM_LENGTH(...) CALC_ARG_LENGTH(__VA_ARGS__)
#if defined(MEM_UCS)
#define MEM_STR(str) CONCAT_STR(L, str)
#define MEM_STR_CMP(str1, str2) wcscmp(str1, str2)
#define MEM_STR_N_CMP(str1, str2, n) wcsncmp(str1, str2, n)
#define MEM_STR_LEN(str) wcslen(str)
#elif defined(MEM_MBCS)
#define MEM_STR(str) str
#define MEM_STR_CMP(str1, str2) strcmp(str1, str2)
#define MEM_STR_N_CMP(str1, str2, n) strncmp(str1, str2, n)
#define MEM_STR_LEN(str) strlen(str)
#endif

#define VA_ARGS(...) , ##__VA_ARGS__
#define MEM_THISCALL(obj, func, ...) obj.func(&obj VA_ARGS(__VA_ARGS__))

//Assembly

#define _MEM_BYTE       0x0
#define _MEM_WORD       0x0, 0x0
#define _MEM_DWORD      0x0, 0x0, 0x0, 0x0
#define _MEM_QWORD      0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0

#if defined(MEM_86)
#define _MEM_DETOUR_METHOD0    0xB8, _MEM_DWORD, 0xFF, 0xE0
#define _MEM_DETOUR_METHOD1    0xE9, _MEM_DWORD
#define _MEM_DETOUR_METHOD2    0xB8, _MEM_DWORD, 0x50, 0xC3
#define _MEM_DETOUR_METHOD3    0x68, _MEM_DWORD, 0xC3
#define _MEM_DETOUR_METHOD4    0xB8, _MEM_DWORD, 0xFF, 0xD0
#define _MEM_DETOUR_METHOD5    0xE8, _MEM_DWORD
#elif defined(MEM_64)
#define _MEM_DETOUR_METHOD0    0x48, 0xB8, _MEM_QWORD, 0xFF, 0xE0
#define _MEM_DETOUR_METHOD1    0xE9, _MEM_DWORD
#define _MEM_DETOUR_METHOD2    0x48, 0xB8, _MEM_QWORD, 0x50, 0xC3
#define _MEM_DETOUR_METHOD3    0x68, _MEM_DWORD, 0xC3
#define _MEM_DETOUR_METHOD4    0x48, 0xB8, _MEM_QWORD, 0xFF, 0xD0
#define _MEM_DETOUR_METHOD5    0xE8, _MEM_DWORD
#endif

#define MEM_DETOUR_INT_METHOD0 0
#define MEM_DETOUR_INT_METHOD1 1
#define MEM_DETOUR_INT_METHOD2 2
#define MEM_DETOUR_INT_METHOD3 3
#define MEM_DETOUR_INT_METHOD4 4
#define MEM_DETOUR_INT_METHOD5 5

//Other
#if defined(__cplusplus)
#define MEM_CPP
#else
#define MEM_C
#endif
#define MEM_BAD_RETURN         -1
#define MEM_RETURN             !MEM_BAD_RETURN
#define MEM_KNOWN_BYTE         MEM_STR('x')
#define MEM_UNKNOWN_BYTE       MEM_STR('?')
#if defined(MEM_WIN)
#elif defined(MEM_LINUX)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#endif

//Compatibility

#if (defined(MEM_WIN) || defined(MEM_LINUX)) && (defined(MEM_86) || defined(MEM_64))
#define MEM_COMPATIBLE
#endif

#if defined(MEM_COMPATIBLE)

//Includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#if defined(MEM_WIN)
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#elif defined(MEM_LINUX)
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
#include <sys/io.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#endif

#ifdef MEM_CPP
extern "C"
{
#endif

typedef enum { mem_false = 0, mem_true = 1 } mem_bool_t;
typedef int                                  mem_int_t;
typedef void                                 mem_void_t;

typedef char                                 mem_int8_t;
typedef short                                mem_int16_t;
typedef int                                  mem_int32_t;
typedef long long                            mem_int64_t;

typedef unsigned char                        mem_uint8_t;
typedef unsigned short                       mem_uint16_t;
typedef unsigned int                         mem_uint32_t;
typedef unsigned long long                   mem_uint64_t;

#if defined(MEM_WIN)
typedef DWORD                                mem_pid_t;
typedef DWORD                                mem_prot_t;
typedef HMODULE                              mem_module_handle_t;
typedef DWORD                                mem_alloc_type_t;
#elif defined(MEM_LINUX)
typedef mem_int32_t                          mem_pid_t;
typedef mem_int32_t                          mem_prot_t;
typedef void*                                mem_module_handle_t;
typedef mem_int32_t                          mem_alloc_type_t;
#endif

#if defined(MEM_86)
typedef mem_int32_t                          mem_intptr_t;
typedef mem_uint32_t                         mem_uintptr_t;
#elif defined(MEM_64)
typedef mem_int64_t                          mem_intptr_t;
typedef mem_uint64_t                         mem_uintptr_t;
#endif

typedef mem_uint8_t                          mem_byte_t;
typedef mem_uint16_t                         mem_word_t;
typedef mem_uint32_t                         mem_dword_t;
typedef mem_uint64_t                         mem_qword_t;

#if defined(MEM_UCS)
typedef wchar_t                              mem_wchar_t;
typedef mem_wchar_t                          mem_char_t;
#elif defined(MEM_MBCS)
typedef mem_uint16_t                         mem_wchar_t;
typedef char                                 mem_char_t;
#endif

typedef mem_byte_t*                          mem_byteptr_t;
typedef mem_int8_t*                          mem_bytearray_t;
typedef mem_void_t*                          mem_voidptr_t;
typedef unsigned long                        mem_size_t;

//mem_string_t

typedef struct _mem_string_t
{
    mem_bool_t  is_initialized;
    mem_char_t* buffer;
    mem_size_t  npos;
    mem_bool_t  (* is_valid)(struct _mem_string_t* p_string);
    mem_void_t  (* clear)   (struct _mem_string_t* p_string);
    mem_void_t  (* empty)   (struct _mem_string_t* p_string);
    mem_size_t  (* size)    (struct _mem_string_t* p_string);
    mem_void_t  (* resize)  (struct _mem_string_t* p_string, mem_size_t size);
    mem_size_t  (* length)  (struct _mem_string_t* p_string);
    mem_char_t* (* begin)   (struct _mem_string_t* p_string);
    mem_char_t* (* end)     (struct _mem_string_t* p_string);
    mem_size_t  (* find)    (struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset);
    mem_size_t  (* rfind)   (struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset);
    mem_size_t  (* count)   (struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset);
    mem_size_t  (* rcount)  (struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset);
    mem_char_t  (* at)      (struct _mem_string_t* p_string, mem_size_t pos);
    mem_void_t  (* value)   (struct _mem_string_t* p_string, const mem_char_t* new_str);
    mem_void_t  (* insert)  (struct _mem_string_t* p_string, const mem_char_t* str);
    mem_void_t  (* replace) (struct _mem_string_t* p_string, const mem_char_t* old_str, const mem_char_t* new_str);
    mem_void_t  (* c_set)   (struct _mem_string_t* p_string, mem_size_t pos, mem_char_t c);
    mem_char_t* (* c_str)   (struct _mem_string_t* p_string);
    mem_bool_t  (* compare) (struct _mem_string_t* p_string, struct _mem_string_t str);
    struct _mem_string_t* (* to_lower)(struct _mem_string_t* p_string);
    struct _mem_string_t* (* to_upper)(struct _mem_string_t* p_string);
    struct _mem_string_t  (* substr)  (struct _mem_string_t* p_string, mem_size_t start, mem_size_t end);
}mem_string_t;

struct _mem_string_t  mem_string_init();
struct _mem_string_t  mem_string_new(const mem_char_t* c_string);
mem_bool_t            mem_string_is_valid(struct _mem_string_t* p_string);
mem_void_t            mem_string_clear   (struct _mem_string_t* p_string);
mem_void_t            mem_string_empty   (struct _mem_string_t* p_string);
mem_size_t            mem_string_size    (struct _mem_string_t* p_string);
mem_void_t            mem_string_resize  (struct _mem_string_t* p_string, mem_size_t size);
mem_size_t            mem_string_length  (struct _mem_string_t* p_string);
mem_char_t*           mem_string_begin   (struct _mem_string_t* p_string);
mem_char_t*           mem_string_end     (struct _mem_string_t* p_string);
mem_size_t            mem_string_find    (struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset);
mem_size_t            mem_string_rfind   (struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset);
mem_size_t            mem_string_count   (struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset);
mem_size_t            mem_string_rcount  (struct _mem_string_t* p_string, const mem_char_t* substr, mem_size_t offset);
mem_char_t            mem_string_at      (struct _mem_string_t* p_string, mem_size_t pos);
mem_void_t            mem_string_insert  (struct _mem_string_t* p_string, const mem_char_t* str);
mem_void_t            mem_string_value   (struct _mem_string_t* p_string, const mem_char_t* new_str);
mem_void_t            mem_string_replace (struct _mem_string_t* p_string, const mem_char_t* old_str, const mem_char_t* new_str);
mem_char_t*           mem_string_c_str   (struct _mem_string_t* p_string);
mem_void_t            mem_string_c_set   (struct _mem_string_t* p_string, mem_size_t pos, mem_char_t c);
mem_bool_t            mem_string_compare (struct _mem_string_t* p_string, struct _mem_string_t str);
struct _mem_string_t* mem_string_to_lower(struct _mem_string_t* p_string);
struct _mem_string_t* mem_string_to_upper(struct _mem_string_t* p_string);
struct _mem_string_t  mem_string_substr  (struct _mem_string_t* p_string, mem_size_t start, mem_size_t end);
mem_void_t            mem_string_free    (struct _mem_string_t* p_string);

//mem_process_t

typedef struct _mem_process_t
{
    mem_bool_t   is_initialized;
    mem_string_t name;
    mem_pid_t    pid;
#   if defined(MEM_WIN)
    HANDLE       handle;
#   elif defined(MEM_LINUX)
#   endif
    mem_bool_t(* is_valid)(struct _mem_process_t* p_process);
    mem_bool_t(* compare)(struct _mem_process_t* p_process, struct _mem_process_t process);
}mem_process_t;

struct _mem_process_t mem_process_init();
mem_bool_t            mem_process_is_valid(struct _mem_process_t* p_process);
mem_bool_t            mem_process_compare(struct _mem_process_t* p_process, struct _mem_process_t process);
mem_void_t            mem_process_free(struct _mem_process_t* p_process);

//mem_process_list_t

typedef struct _mem_process_list_t
{
    mem_size_t     _length;
    mem_process_t* _buffer;
    mem_bool_t     is_initialized;

    mem_process_t (* at)      (struct _mem_process_list_t* p_process_list, mem_size_t pos);
    mem_bool_t    (* is_valid)(struct _mem_process_list_t* p_process_list);
    mem_size_t    (* length)  (struct _mem_process_list_t* p_process_list);
    mem_process_t*(* buffer)  (struct _mem_process_list_t* p_process_list);
    mem_size_t    (* size)    (struct _mem_process_list_t* p_process_list);
    mem_void_t    (* resize)  (struct _mem_process_list_t* p_process_list, mem_size_t size);
    mem_void_t    (* append)  (struct _mem_process_list_t* p_process_list, mem_process_t process);
}mem_process_list_t;

mem_process_list_t    mem_process_list_init();
mem_process_t         mem_process_list_at      (struct _mem_process_list_t* p_process_list, mem_size_t pos);
mem_bool_t            mem_process_list_is_valid(struct _mem_process_list_t* p_process_list);
mem_size_t            mem_process_list_length  (struct _mem_process_list_t* p_process_list);
mem_process_t*        mem_process_list_buffer  (struct _mem_process_list_t* p_process_list);
mem_size_t            mem_process_list_size    (struct _mem_process_list_t* p_process_list);
mem_void_t            mem_process_list_resize  (struct _mem_process_list_t* p_process_list, mem_size_t size);
mem_void_t            mem_process_list_append  (struct _mem_process_list_t* p_process_list, mem_process_t process);


//mem_module_t

typedef struct _mem_module_t
{
    mem_bool_t is_initialized;
    mem_string_t name;
    mem_string_t path;
    mem_voidptr_t base;
    mem_voidptr_t end;
    mem_uintptr_t size;
    mem_module_handle_t handle;
    mem_bool_t(* is_valid)(struct _mem_module_t* p_mod);
    mem_bool_t(* compare)(struct _mem_module_t* p_mod, struct _mem_module_t mod);
}mem_module_t;

struct _mem_module_t mem_module_init();
mem_bool_t           mem_module_is_valid(struct _mem_module_t* p_mod);
mem_bool_t           mem_module_compare(struct _mem_module_t* p_mod, struct _mem_module_t mod);
mem_void_t           mem_module_free(struct _mem_module_t* p_mod);

//mem_module_list_t

typedef struct _mem_module_list_t
{
    mem_size_t    _length;
    mem_module_t* _buffer;
    mem_bool_t    is_initialized;

    mem_module_t  (* at)      (struct _mem_module_list_t* p_module_list, mem_size_t pos);
    mem_bool_t    (* is_valid)(struct _mem_module_list_t* p_module_list);
    mem_size_t    (* length)  (struct _mem_module_list_t* p_module_list);
    mem_module_t* (* buffer)  (struct _mem_module_list_t* p_module_list);
    mem_size_t    (* size)    (struct _mem_module_list_t* p_module_list);
    mem_void_t    (* resize)  (struct _mem_module_list_t* p_module_list, mem_size_t size);
    mem_void_t    (* append)  (struct _mem_module_list_t* p_module_list, mem_module_t process);
}mem_module_list_t;

mem_module_list_t     mem_module_list_init();
mem_module_t          mem_module_list_at      (struct _mem_module_list_t* p_module_list, mem_size_t pos);
mem_bool_t            mem_module_list_is_valid(struct _mem_module_list_t* p_module_list);
mem_size_t            mem_module_list_length  (struct _mem_module_list_t* p_module_list);
mem_module_t*         mem_module_list_buffer  (struct _mem_module_list_t* p_module_list);
mem_size_t            mem_module_list_size    (struct _mem_module_list_t* p_module_list);
mem_void_t            mem_module_list_resize  (struct _mem_module_list_t* p_module_list, mem_size_t size);
mem_void_t            mem_module_list_append  (struct _mem_module_list_t* p_module_list, mem_module_t mod);

//mem_alloc_t

typedef struct _mem_alloc_t
{
    mem_bool_t is_initialized;
    mem_prot_t protection;
    mem_alloc_type_t type;
    mem_bool_t(* is_valid)(struct _mem_alloc_t* p_alloc);
}mem_alloc_t;

struct _mem_alloc_t mem_alloc_init();
mem_bool_t          mem_alloc_is_valid(struct _mem_alloc_t* p_alloc);

//mem_lib_t

typedef struct _mem_lib_t
{
    mem_bool_t is_initialized;
    mem_string_t path;
#   if defined(MEM_WIN)
#   elif defined(MEM_LINUX)
    mem_int_t    mode;
#   endif
    mem_bool_t(* is_valid)(struct _mem_lib_t* p_lib);
}mem_lib_t;

struct _mem_lib_t  mem_lib_init();
mem_bool_t         mem_lib_is_valid(struct _mem_lib_t* p_lib);

//mem_detour_t

typedef enum _mem_detour_t
{
    MEM_DT_M0 = MEM_DETOUR_INT_METHOD0,
    MEM_DT_M1 = MEM_DETOUR_INT_METHOD1,
    MEM_DT_M2 = MEM_DETOUR_INT_METHOD2,
    MEM_DT_M3 = MEM_DETOUR_INT_METHOD3,
    MEM_DT_M4 = MEM_DETOUR_INT_METHOD4,
    MEM_DT_M5 = MEM_DETOUR_INT_METHOD5
}mem_detour_t;

//libmem

mem_string_t       mem_parse_mask(mem_string_t mask);
mem_uintptr_t      mem_get_page_size();

//ex
mem_pid_t          mem_ex_get_pid(mem_string_t process_name);
mem_string_t       mem_ex_get_process_name(mem_pid_t pid);
mem_process_t      mem_ex_get_process(mem_pid_t pid);
mem_process_list_t mem_ex_get_process_list();
mem_module_t       mem_ex_get_module(mem_process_t process, mem_string_t module_name);
mem_module_list_t  mem_ex_get_module_list(mem_process_t process);
mem_bool_t         mem_ex_is_process_running(mem_process_t process);
mem_int_t          mem_ex_read(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size);
mem_int_t          mem_ex_write(mem_process_t process, mem_voidptr_t src, mem_voidptr_t data, mem_size_t size);
mem_int_t          mem_ex_set(mem_process_t process, mem_voidptr_t dst, mem_byte_t byte, mem_size_t size);
mem_int_t          mem_ex_protect(mem_process_t process, mem_voidptr_t src, mem_size_t size, mem_prot_t protection);
mem_voidptr_t      mem_ex_allocate(mem_process_t process, mem_size_t size, mem_prot_t protection);
mem_int_t          mem_ex_deallocate(mem_process_t process, mem_voidptr_t src, mem_size_t size);
mem_voidptr_t      mem_ex_scan(mem_process_t process, mem_bytearray_t data, mem_voidptr_t base, mem_voidptr_t end, mem_size_t size);
mem_voidptr_t      mem_ex_pattern_scan(mem_process_t process, mem_bytearray_t pattern, mem_string_t mask, mem_voidptr_t base, mem_voidptr_t end);
mem_int_t          mem_ex_detour(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_bytearray_t* stolen_bytes);
mem_voidptr_t      mem_ex_detour_trampoline(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_bytearray_t* stolen_bytes);
mem_void_t         mem_ex_detour_restore(mem_process_t process, mem_voidptr_t src, mem_bytearray_t stolen_bytes, mem_size_t size);
mem_int_t          mem_ex_load_library(mem_process_t process, mem_lib_t lib);
mem_voidptr_t      mem_ex_get_symbol(mem_module_t mod, const char* symbol);

//in

mem_pid_t         mem_in_get_pid();
mem_process_t     mem_in_get_process();
mem_string_t      mem_in_get_process_name();
mem_module_t      mem_in_get_module(mem_string_t module_name);
mem_module_list_t mem_in_get_module_list();
mem_voidptr_t     mem_in_pattern_scan(mem_bytearray_t pattern, mem_string_t mask, mem_voidptr_t base, mem_voidptr_t end);
mem_void_t        mem_in_read(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size);
mem_void_t        mem_in_write(mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size);
mem_void_t        mem_in_set(mem_voidptr_t src, mem_byte_t byte, mem_size_t size);
mem_int_t         mem_in_protect(mem_voidptr_t src, mem_size_t size, mem_prot_t protection);
mem_voidptr_t     mem_in_allocate(mem_size_t size, mem_prot_t protection);
mem_void_t        mem_in_deallocate(mem_voidptr_t src, mem_size_t size);
mem_bool_t        mem_in_compare(mem_voidptr_t pdata1, mem_voidptr_t pdata2, mem_size_t size);
mem_voidptr_t     mem_in_scan(mem_voidptr_t data, mem_voidptr_t base, mem_voidptr_t end, mem_size_t size);
mem_size_t        mem_in_detour_length(mem_detour_t method);
mem_int_t         mem_in_detour(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_bytearray_t* stolen_bytes);
mem_voidptr_t     mem_in_detour_trampoline(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_bytearray_t* stolen_bytes);
mem_void_t        mem_in_detour_restore(mem_voidptr_t src, mem_bytearray_t stolen_bytes, mem_size_t size);
mem_module_t      mem_in_load_library(mem_lib_t lib);
mem_void_t        mem_in_unload_library(mem_module_t mod);
mem_voidptr_t     mem_in_get_symbol(mem_module_t mod, const char* symbol);

#ifdef MEM_CPP
}
#endif

#endif //MEM_COMPATIBLE
#endif //MEM