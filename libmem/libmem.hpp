/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |  https://github.com/rdbo/libmem  |
 *  ----------------------------------
 */

#pragma once
#ifndef LIBMEM_HPP
#define LIBMEM_HPP

#include "libmem.h"
#include <iostream>
#include <string>
#include <vector>

typedef std::basic_string<mem_tchar_t>   mem_string_t;

namespace mem
{
	namespace in
	{
		inline mem_pid_t                    get_pid() { return mem_in_get_pid(); }
		inline mem_size_t                   get_process_name(mem_tstring_t* pprocess_name) { return mem_in_get_process_name(pprocess_name); }
		inline mem_string_t                 get_process_name()
		{
			mem_tstring_t process_name = (mem_tstring_t)NULL;
			size_t read_chars = mem_in_get_process_name(&process_name);
			mem_string_t  str = (read_chars ? process_name : MEM_STR(""));
			return str;
		}
		inline mem_size_t                   get_process_path(mem_tstring_t* pprocess_path) { return mem_in_get_process_path(pprocess_path); }
		inline mem_string_t                 get_process_path()
		{
			mem_tstring_t process_path = (mem_tstring_t)NULL;
			size_t read_chars = mem_in_get_process_path(&process_path);
			mem_string_t  str = (read_chars ? process_path : MEM_STR(""));
			return str;
		}
		inline mem_arch_t                   get_arch() { return mem_in_get_arch(); }
		inline mem_process_t                get_process() { return mem_in_get_process(); }
		inline mem_module_t                 get_module(mem_tstring_t module_ref) { return mem_in_get_module(module_ref); }
		inline mem_module_t                 get_module(mem_string_t module_ref)  { return mem_in_get_module((mem_tstring_t)module_ref.c_str()); }
		inline mem_size_t                   get_module_name(mem_module_t mod, mem_tstring_t* pmodule_name) { return mem_in_get_module_name(mod, pmodule_name); }
		inline mem_string_t                 get_module_name(mem_module_t mod)
		{
			mem_tstring_t module_name = (mem_tstring_t)NULL;
			size_t read_chars = mem_in_get_module_name(mod, &module_name);
			mem_string_t  str = (read_chars ? module_name : MEM_STR(""));
			return str;
		}
		inline mem_size_t                   get_module_path(mem_module_t mod, mem_tstring_t* pmodule_path) { return mem_in_get_module_path(mod, pmodule_path); }
		inline mem_string_t                 get_module_path(mem_module_t mod)
		{
			mem_tstring_t module_path = (mem_tstring_t)NULL;
			size_t read_chars = mem_in_get_module_path(mod, &module_path);
			mem_string_t  str = (read_chars ? module_path : MEM_STR(""));
			return str;
		}
		inline mem_size_t                   get_module_list(mem_module_t** pmodule_list) { return mem_in_get_module_list(pmodule_list); }
		inline std::vector<mem_module_t>    get_module_list()
		{
			mem_module_t* module_list = (mem_module_t*)NULL;
			size_t size = mem_in_get_module_list(&module_list);
			std::vector<mem_module_t> mod_list = {};
			for (mem_size_t i = 0; i < size; ++i)
				mod_list.push_back(module_list[i]);
			return mod_list;
		}
		inline mem_page_t                   get_page(mem_voidptr_t src) { return mem_in_get_page(src); }
		inline mem_bool_t                   read(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size) { return mem_in_read(src, dst, size); }
		inline mem_bool_t                   write(mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size) { return mem_in_write(dst, src, size); }
		inline mem_bool_t                   set(mem_voidptr_t src, mem_byte_t byte, mem_size_t size) { return mem_in_set(src, byte, size); }
		inline mem_voidptr_t                syscall(mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5) { return mem_in_syscall(syscall_n, arg0, arg1, arg2, arg3, arg4, arg5); }
		inline mem_bool_t                   protect(mem_voidptr_t src, mem_size_t size, mem_prot_t protection, mem_prot_t* pold_protection) { return mem_in_protect(src, size, protection, pold_protection); }
		inline mem_voidptr_t                allocate(mem_size_t size, mem_prot_t protection) { return mem_in_allocate(size, protection); }
		inline mem_bool_t                   deallocate(mem_voidptr_t src, mem_size_t size) { return mem_in_deallocate(src, size); }
		inline mem_voidptr_t                scan(mem_data_t data, mem_size_t size, mem_voidptr_t start, mem_voidptr_t stop) { return mem_in_scan(data, size, start, stop); }
		inline mem_voidptr_t                pattern_scan(mem_data_t pattern, mem_tstring_t mask, mem_voidptr_t start, mem_voidptr_t stop) { return mem_in_pattern_scan(pattern, mask, start, stop); }
		inline mem_voidptr_t                pattern_scan(mem_data_t pattern, mem_string_t mask, mem_voidptr_t start, mem_voidptr_t stop) { return mem_in_pattern_scan(pattern, (mem_tstring_t)mask.c_str(), start, stop); }
		inline mem_size_t                   detour_size(mem_detour_t method) { return mem_in_detour_size(method); }
		inline mem_bool_t                   detour(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_data_t* stolen_bytes) { return mem_in_detour(src, dst, size, method, stolen_bytes); }
		inline mem_voidptr_t                detour_trampoline(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_data_t* stolen_bytes) { return mem_in_detour_trampoline(src, dst, size, method, stolen_bytes); }
		inline mem_bool_t                   detour_restore(mem_voidptr_t src, mem_data_t stolen_bytes, mem_size_t size) { return mem_in_detour_restore(src, stolen_bytes, size); }
		inline mem_module_t                 load_module(mem_tstring_t path) { return mem_in_load_module(path); }
		inline mem_module_t                 load_module(mem_string_t path) { return mem_in_load_module((mem_tstring_t)path.c_str()); }
		inline mem_bool_t                   unload_module(mem_module_t mod) { return mem_in_unload_module(mod); }
		inline mem_voidptr_t                get_symbol(mem_module_t mod, mem_cstring_t symbol) { return mem_in_get_symbol(mod, symbol); }
		inline mem_voidptr_t                get_symbol(mem_module_t mod, mem_string_t symbol) { return mem_in_get_symbol(mod, (mem_cstring_t)symbol.c_str()); }
	}

	namespace ex
	{
		inline mem_pid_t                    get_pid(mem_tstring_t process_ref) { return mem_ex_get_pid(process_ref); }
		inline mem_pid_t                    get_pid(mem_string_t process_ref) { return mem_ex_get_pid((mem_tstring_t)process_ref.c_str()); }
		inline mem_size_t                   get_process_name(mem_pid_t pid, mem_tstring_t* pprocess_name) { return mem_ex_get_process_name(pid, pprocess_name); }
		inline mem_string_t                 get_process_name(mem_pid_t pid)
		{
			mem_tstring_t process_name = (mem_tstring_t)NULL;
			size_t read_chars = mem_ex_get_process_name(pid, &process_name);
			mem_string_t  str = (read_chars ? process_name : MEM_STR(""));
			return str;
		}
		inline mem_string_t                 get_process_name(mem_process_t process)
		{
			mem_pid_t pid = process.pid;
			return mem::ex::get_process_name(pid);
		}
		inline mem_size_t                   get_process_path(mem_pid_t pid, mem_tstring_t* pprocess_path) { return mem_ex_get_process_path(pid, pprocess_path); }
		inline mem_string_t                 get_process_path(mem_pid_t pid)
		{
			mem_tstring_t process_path = (mem_tstring_t)NULL;
			size_t read_chars = mem_ex_get_process_path(pid, &process_path);
			mem_string_t  str = (read_chars ? process_path : MEM_STR(""));
			return str;
		}
		inline mem_string_t                 get_process_path(mem_process_t process)
		{
			mem_pid_t pid = process.pid;
			return mem::ex::get_process_path(pid);
		}
		inline mem_arch_t                   get_system_arch() { return mem_ex_get_system_arch(); }
		inline mem_arch_t                   get_arch(mem_pid_t pid) { return mem_ex_get_arch(pid); }
		inline mem_process_t                get_process(mem_pid_t pid) { return mem_ex_get_process(pid); }
		inline mem_size_t                   get_process_list(mem_process_t** pprocess_list) { return mem_ex_get_process_list(pprocess_list); }
		inline std::vector<mem_process_t>   get_process_list()
		{
			mem_process_t* process_list = (mem_process_t*)NULL;
			size_t size = mem_ex_get_process_list(&process_list);
			std::vector<mem_process_t> proc_list = {};
			for (mem_size_t i = 0; i < size; ++i)
				proc_list.push_back(process_list[i]);
			return proc_list;
		}
		inline mem_module_t                 get_module(mem_process_t process, mem_tstring_t module_ref) { return mem_ex_get_module(process, module_ref); }
		inline mem_module_t                 get_module(mem_process_t process, mem_string_t module_ref) { return mem_ex_get_module(process, (mem_tstring_t)module_ref.c_str()); }
		inline mem_size_t                   get_module_name(mem_process_t process, mem_module_t mod, mem_tstring_t* pmodule_name) { return mem_ex_get_module_name(process, mod, pmodule_name); }
		inline mem_string_t                 get_module_name(mem_process_t process, mem_module_t mod)
		{
			mem_tstring_t module_name = (mem_tstring_t)NULL;
			size_t read_chars = mem_ex_get_module_name(process, mod, &module_name);
			mem_string_t  str = (read_chars ? module_name : MEM_STR(""));
			return str;
		}
		inline mem_size_t                   get_module_path(mem_process_t process, mem_module_t mod, mem_tstring_t* pmodule_path) { return mem_ex_get_module_path(process, mod, pmodule_path); }
		inline mem_string_t                 get_module_path(mem_process_t process, mem_module_t mod)
		{
			mem_tstring_t module_path = (mem_tstring_t)NULL;
			size_t read_chars = mem_ex_get_module_path(process, mod, &module_path);
			mem_string_t  str = (read_chars ? module_path : MEM_STR(""));
			return str;
		}
		inline mem_size_t                   get_module_list(mem_process_t process, mem_module_t** pmodule_list) { return mem_ex_get_module_list(process, pmodule_list); }
		inline std::vector<mem_module_t>    get_module_list(mem_process_t process)
		{
			mem_module_t* module_list = (mem_module_t*)NULL;
			size_t size = mem_ex_get_module_list(process, &module_list);
			std::vector<mem_module_t> mod_list = {};
			for (mem_size_t i = 0; i < size; ++i)
				mod_list.push_back(module_list[i]);
			return mod_list;
		}
		inline mem_page_t                   get_page(mem_process_t process, mem_voidptr_t src) { return mem_ex_get_page(process, src); }
		inline mem_bool_t                   is_process_running(mem_process_t process) { return mem_ex_is_process_running(process); }
		inline mem_bool_t                   read(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size) { return mem_ex_read(process, src, dst, size); }
		inline mem_bool_t                   write(mem_process_t process, mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size) { return mem_ex_write(process, dst, src, size); }
		inline mem_bool_t                   set(mem_process_t process, mem_voidptr_t dst, mem_byte_t byte, mem_size_t size) { return mem_ex_set(process, dst, byte, size); }
		inline mem_voidptr_t                syscall(mem_process_t process, mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5) { return mem_ex_syscall(process, syscall_n, arg0, arg1, arg2, arg3, arg4, arg5); }
		inline mem_bool_t                   protect(mem_process_t process, mem_voidptr_t src, mem_size_t size, mem_prot_t protection, mem_prot_t* pold_protection) { return mem_ex_protect(process, src, size, protection, pold_protection); }
		inline mem_voidptr_t                allocate(mem_process_t process, mem_size_t size, mem_prot_t protection) { return mem_ex_allocate(process, size, protection); }
		inline mem_bool_t                   deallocate(mem_process_t process, mem_voidptr_t src, mem_size_t size) { return mem_ex_deallocate(process, src, size); }
		inline mem_voidptr_t                scan(mem_process_t process, mem_data_t data, mem_size_t size, mem_voidptr_t start, mem_voidptr_t stop) { return mem_ex_scan(process, data, size, start, stop); }
		inline mem_voidptr_t                pattern_scan(mem_process_t process, mem_data_t pattern, mem_tstring_t mask, mem_voidptr_t start, mem_voidptr_t stop) { return mem_ex_pattern_scan(process, pattern, mask, start, stop); }
		inline mem_voidptr_t                pattern_scan(mem_process_t process, mem_data_t pattern, mem_string_t mask, mem_voidptr_t start, mem_voidptr_t stop) { return mem_ex_pattern_scan(process, pattern, (mem_tstring_t)mask.c_str(), start, stop); }
		inline mem_module_t                 load_module(mem_process_t process, mem_tstring_t path) { return mem_ex_load_module(process, path); }
		inline mem_module_t                 load_module(mem_process_t process, mem_string_t path) { return mem_ex_load_module(process, (mem_tstring_t)path.c_str()); }
		inline mem_bool_t                   unload_module(mem_process_t process, mem_module_t mod) { return mem_ex_unload_module(process, mod); }
		inline mem_voidptr_t                get_symbol(mem_process_t process, mem_module_t mod, mem_cstring_t symbol) { return mem_ex_get_symbol(process, mod, symbol); }
	}
}

#endif //LIBMEM_HPP
