/* libmem++ - C++ version of libmem
 * by rdbo
 * ---------------------------------
 * https://github.com/rdbo/libmem
 * ---------------------------------
 */

#ifndef LIBMEM_HPP
#define LIBMEM_HPP

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
#define MEM_STR_STR(str1, str2) wcsstrstr(str1, str2)
#define MEM_STR_TO_PTR(str) (void*)wcstoul(str, NULL, 16)
#elif defined(MEM_MBCS)
#define MEM_STR(str) str
#define MEM_STR_CMP(str1, str2) strcmp(str1, str2)
#define MEM_STR_N_CMP(str1, str2, n) strncmp(str1, str2, n)
#define MEM_STR_LEN(str) strlen(str)
#define MEM_STR_STR(str1, str2) strstr(str1, str2)
#define MEM_STR_TO_PTR(str) (void*)strtoul(str, NULL, 16)
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
#define MEM_BAD                -1
#define MEM_GOOD               !MEM_BAD
#define MEM_NULL               0
#define MEM_FALSE              false
#define MEM_TRUE               true
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
#include <iostream>
#include <sstream>
#include <fstream>
#include <memory>
#include <unordered_map>
#include <vector>
#include <cstring>
#include <cstdint>
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


namespace mem
{
	typedef bool                                 bool_t;
	typedef int                                  int_t;
	typedef void                                 void_t;

	typedef ::int8_t                             int8_t;
	typedef ::int16_t                            int16_t;
	typedef ::int32_t                            int32_t;
	typedef ::int64_t                            int64_t;

	typedef ::uint8_t                            uint8_t;
	typedef ::uint16_t                           uint16_t;
	typedef ::uint32_t                           uint32_t;
	typedef ::uint64_t                           uint64_t;

#if defined(MEM_WIN)
	typedef DWORD                                pid_t;
	typedef DWORD                                prot_t;
	typedef HMODULE                              module_handle_t;
	typedef DWORD                                alloc_type_t;
	typedef DWORD                                flags_t;
#elif defined(MEM_LINUX)
	typedef int32_t                              pid_t;
	typedef int32_t                              prot_t;
	typedef void* module_handle_t;
	typedef int32_t                              alloc_type_t;
	typedef int32_t                              flags_t;
#endif

	/*
#	if defined(MEM_86)
	typedef int32_t                              intptr_t;
	typedef uint32_t                             uintptr_t;
#	elif defined(MEM_64)
	typedef int64_t                              intptr_t;
	typedef uint64_t                             uintptr_t;
#	endif
	*/

	typedef ::intptr_t                           intptr_t;
	typedef ::uintptr_t                          uintptr_t;

	typedef uint8_t                              byte_t;
	typedef uint16_t                             word_t;
	typedef uint32_t                             dword_t;
	typedef uint64_t                             qword_t;

#if defined(MEM_UCS)
	//typedef wchar_t                            wchar_t;
	typedef wchar_t                              char_t;
#elif defined(MEM_MBCS)
	//typedef uint16_t                           wchar_t;
	typedef char                                 char_t;
#endif

	typedef char_t*                              cstring_t;

	typedef byte_t*                              byteptr_t;
	typedef int8_t*                              bytearray_t;
	typedef void_t*                              voidptr_t;
	typedef ::size_t                             size_t;

	//mem::string_t
	typedef std::basic_string<char_t>            string_t;

	//mem::data_t
	typedef std::vector<byte_t>                  data_t;

	//mem::process_t
	class process_t
	{
		public:
		string_t name = MEM_STR("");
		pid_t    pid  = (pid_t)-1;
#		if defined(MEM_WIN)
		HANDLE       handle = INVALID_HANDLE_VALUE;
#		elif defined(MEM_LINUX)
#		endif

		public:
		process_t();
		~process_t();
		bool_t operator==(process_t& process);

		public:
		bool_t is_valid();
	};

	//mem::process_list_t
	typedef std::vector<process_t> process_list_t;

	//mem::module_t
	class module_t
	{
		public:
		string_t  name = MEM_STR("");
		string_t  path = MEM_STR("");
		voidptr_t base = (voidptr_t)-1;
		voidptr_t end  = (voidptr_t)-1;
		uintptr_t size = (uintptr_t)-1;
		module_handle_t handle = (module_handle_t)-1;

		public:
		module_t();
		~module_t();
		bool_t operator==(module_t& mod);

		public:
		bool_t is_valid();
	};

	//mem::module_list_t
	typedef std::vector<module_t> module_list_t;

	//mem::page_t
	class page_t
	{
		public:
		voidptr_t base  = (voidptr_t)-1;
		uintptr_t size  = (uintptr_t)-1;
		voidptr_t end   = (voidptr_t)-1;
		flags_t   flags = (flags_t)-1;
		prot_t    protection = (prot_t)-1;

		public:
		page_t();
		~page_t();

		public:
		bool_t is_valid();
	};

	//mem::alloc_t

	class alloc_t
	{
		public:
		prot_t protection = (prot_t)-1;
		alloc_type_t type = (alloc_type_t)-1;

		public:
		alloc_t();
		alloc_t(prot_t prot);
		alloc_t(prot_t prot, alloc_type_t type);
		~alloc_t();

		public:
		bool_t is_valid();
	};

	class lib_t
	{
		public:
		string_t path = MEM_STR("");
#		if defined(MEM_WIN)
#		elif defined(MEM_LINUX)
		int_t mode;
#		endif

		public:
		lib_t();
		lib_t(string_t path);
		lib_t(string_t path, int_t mode);

		public:
		bool_t is_valid();
	};

	class vtable_t
	{
		public:
		voidptr_t* table = (voidptr_t*)-1;
		std::unordered_map<size_t, voidptr_t> orig_table = {};

		public:
		vtable_t(voidptr_t* vtable);
		~vtable_t();

		public:
		bool_t is_valid();
        voidptr_t get_function(size_t index);
        voidptr_t get_original(size_t index);
		bool_t hook(size_t index, voidptr_t dst);
		bool_t restore(size_t index);
		bool_t restore_all();
	};

	typedef enum
	{
		MEM_DT_M0 = MEM_DETOUR_INT_METHOD0,
		MEM_DT_M1 = MEM_DETOUR_INT_METHOD1,
		MEM_DT_M2 = MEM_DETOUR_INT_METHOD2,
		MEM_DT_M3 = MEM_DETOUR_INT_METHOD3,
		MEM_DT_M4 = MEM_DETOUR_INT_METHOD4,
		MEM_DT_M5 = MEM_DETOUR_INT_METHOD5
	}detour_t;

	//libmem

	string_t       parse_mask(string_t mask);
	uintptr_t      get_page_size();

	namespace ex
	{
		pid_t          get_pid(string_t process_name);
		string_t       get_process_name(pid_t pid);
		process_t      get_process(pid_t pid);
		process_t      get_process(string_t process_name);
		process_list_t get_process_list();
		module_t       get_module(process_t process, string_t module_name);
		module_list_t  get_module_list(process_t process);
		page_t         get_page(process_t process, voidptr_t src);
		bool_t         is_process_running(process_t process);
		bool_t         read(process_t process, voidptr_t src, voidptr_t dst, size_t size);
		template <typename type_t>
		type_t         read(process_t process, voidptr_t src)
		{
			type_t buf;
			memset(&buf, 0x0, sizeof(buf));
			read(process, src, &buf, sizeof(buf));
			return buf;
		}
		bool_t         write(process_t process, voidptr_t dst, voidptr_t src, size_t size);
		template <typename type_t>
		bool_t         write(process_t process, voidptr_t dst, type_t src)
		{
			return write(process, dst, &src, sizeof(src));
		}
		bool_t         set(process_t process, voidptr_t dst, byte_t byte, size_t size);
		voidptr_t      syscall(process_t process, int_t syscall_n, voidptr_t arg0, voidptr_t arg1, voidptr_t arg2, voidptr_t arg3, voidptr_t arg4, voidptr_t arg5);
		bool_t         protect(process_t process, voidptr_t src, size_t size, prot_t protection);
		voidptr_t      allocate(process_t process, size_t size, prot_t protection);
		bool_t         deallocate(process_t process, voidptr_t src, size_t size);
		voidptr_t      scan(process_t process, data_t data, voidptr_t start, voidptr_t stop);
		voidptr_t      pattern_scan(process_t process, data_t pattern, string_t mask, voidptr_t start, voidptr_t stop);
		module_t       load_library(process_t process, lib_t lib);
		voidptr_t      get_symbol(module_t mod, const char* symbol);
	}

	namespace in
	{
		pid_t         get_pid();
		process_t     get_process();
		string_t      get_process_name();
		module_t      get_module(string_t module_name);
		module_list_t get_module_list();
		page_t        get_page(voidptr_t src);
		bool_t        read(voidptr_t src, voidptr_t dst, size_t size);
		template <typename type_t>
		type_t        read(voidptr_t src)
		{
			type_t buf{0};
			read(src, &buf, sizeof(buf));
			return buf;
		}
		bool_t        write(voidptr_t dst, voidptr_t src, size_t size);
		template <typename type_t>
		bool_t        write(voidptr_t dst, type_t src)
		{
			return write(dst, &src, sizeof(src));
		}
		bool_t        set(voidptr_t src, byte_t byte, size_t size);
		voidptr_t     scan(data_t data, voidptr_t start, voidptr_t stop);
		voidptr_t     pattern_scan(data_t pattern, string_t mask, voidptr_t start, voidptr_t stop);
		voidptr_t     syscall(int_t syscall_n, voidptr_t arg0, voidptr_t arg1, voidptr_t arg2, voidptr_t arg3, voidptr_t arg4, voidptr_t arg5);
		int_t         protect(voidptr_t src, size_t size, prot_t protection);
		voidptr_t     allocate(size_t size, prot_t protection);
		bool_t        deallocate(voidptr_t src, size_t size);
		size_t        detour_length(detour_t method);
		int_t         detour(voidptr_t src, voidptr_t dst, size_t size, detour_t method = MEM_DT_M0, byte_t** stolen_bytes = NULL);
		voidptr_t     detour_trampoline(voidptr_t src, voidptr_t dst, size_t size, detour_t method = MEM_DT_M0, byte_t** stolen_bytes = NULL);
		bool_t        detour_restore(voidptr_t src, byte_t* stolen_bytes, size_t size);
		module_t      load_library(lib_t lib);
		bool_t        unload_library(module_t mod);
		voidptr_t     get_symbol(module_t mod, const char* symbol);
	}

}
#endif //MEM_COMPATBILE
#endif
