//Made by rdbo
//https://github.com/rdbo/libmem
//This in an *experimental* C++ wrap for libmem.h

#pragma once
#ifndef LIBMEM_HPP
#define LIBMEM_HPP

#include "libmem.h"

#if defined(MEM_CPP) && defined(MEM_COMPATIBLE)

namespace mem
{
    typedef mem_bool_t          bool_t;
    typedef mem_int_t           int_t;
    typedef mem_void_t          void_t;

    typedef mem_int8_t          int8_t;
    typedef mem_int16_t         int16_t;
    typedef mem_int32_t         int32_t;
    typedef mem_int64_t         int64_t;

    typedef mem_uint8_t         uint8_t;
    typedef mem_uint16_t        uint16_t;
    typedef mem_uint32_t        uint32_t;
    typedef mem_uint64_t        uint64_t;

    typedef mem_pid_t           pid_t;
    typedef mem_prot_t          prot_t;
    typedef mem_module_handle_t module_handle_t;
    typedef mem_alloc_type_t    alloc_type_t;
    typedef mem_flags_t         flags_t;

    typedef mem_intptr_t        intptr_t;
    typedef mem_uintptr_t       uintptr_t;
    typedef mem_byte_t          byte_t;
    typedef mem_word_t          word_t;
    typedef mem_dword_t         dword_t;
    typedef mem_qword_t         qword_t;

    //typedef mem_wchar_t       wchar_t;
    typedef mem_char_t          char_t;
    typedef mem_char_t*         cstring_t;

    typedef mem_byteptr_t       byteptr_t;
    typedef mem_byte_t          byte_t;
    typedef mem_voidptr_t       voidptr_t;
    typedef mem_size_t          size_t;

    class string_t : public _mem_string_t
    {
        public:
        mem_bool_t              is_valid() { return mem_string_is_valid(this); }
        mem_void_t              clear   () { return mem_string_clear(this); }
        mem_void_t              empty   () { return mem_string_empty(this); }
        mem_size_t              size    () { return mem_string_size(this); }
        mem_void_t              resize  (mem_size_t _size) { return mem_string_resize(this, _size); }
        mem_size_t              length  () { return mem_string_length(this); }
        mem_char_t*             begin   () { return mem_string_begin(this); }
        mem_char_t*             end     () { return mem_string_end(this); }
        mem_size_t              find    (const mem_char_t* substr, mem_size_t offset) { return mem_string_find(this, substr, offset); }
        mem_size_t              rfind   (const mem_char_t* substr, mem_size_t offset) { return mem_string_rfind(this, substr, offset); }
        mem_size_t              count   (const mem_char_t* substr, mem_size_t offset) { return mem_string_count(this, substr, offset); }
        mem_size_t              rcount  (const mem_char_t* substr, mem_size_t offset) { return mem_string_rcount(this, substr, offset); } 
        mem_char_t              at      (mem_size_t pos) { return mem_string_at(this, pos); }
        mem_void_t              insert  (const mem_char_t* _str) { return mem_string_insert(this, _str); }
        mem_void_t              value   (const mem_char_t* new_str) { return mem_string_value(this, new_str); }
        mem_void_t              replace (const mem_char_t* old_str, const mem_char_t* new_str) { return mem_string_replace(this, old_str, new_str); }
        mem_void_t              reverse () { return mem_string_reverse(this); }
        mem_char_t*             c_str   () { return mem_string_c_str(this); }
        mem_void_t              c_set   (mem_size_t pos, mem_char_t c) { return mem_string_c_set(this, pos, c); }
        mem_bool_t              compare (struct _mem_string_t _str) { return mem_string_compare(this, _str); }
        struct _mem_string_t*   to_lower() { return mem_string_to_lower(this); }
        struct _mem_string_t*   to_upper() { return mem_string_to_upper(this); }
        string_t                substr  (mem_size_t start, mem_size_t end) { return string_t(mem_string_substr(this, start, end)); }

        public:

        string_t() { *(struct _mem_string_t*)this = mem_string_init(); }
        string_t(const mem_char_t* c_string) { *(struct _mem_string_t*)this = mem_string_new(c_string); }
        string_t(struct _mem_string_t _str) { *(struct _mem_string_t*)this = _str; }
        ~string_t() { /*mem_string_free((struct _mem_string_t*)this);*/ }

        string_t operator=(const mem_char_t* c_string)
        {
            this->~string_t();
            return mem_string_new(c_string);
        }

        string_t operator=(mem_string_t _str)
        {
            this->~string_t();
            return string_t(_str);
        }

        bool operator==(const mem_char_t* c_string)
        {
            return (bool)MEM_STR_CMP(this->buffer, c_string);
        }

        bool operator==(mem_string_t _str)
        {
            return (bool)compare(_str);
        }

        mem_char_t operator[](mem_size_t pos)
        {
            return at(pos);
        }
    };

    class process_t : public mem_process_t
    {
        public:
        mem_bool_t is_valid() { return mem_process_is_valid(this); }
        mem_bool_t compare (struct _mem_process_t _process) { return mem_process_compare(this, _process); }

        public:

        process_t() { *(struct _mem_process_t*)this = mem_process_init(); }
        process_t(struct _mem_process_t _process) { *(struct _mem_process_t*)this = _process; }
        ~process_t() { /*mem_process_free(this);*/ }

        process_t operator=(struct _mem_process_t _process)
        {
            this->~process_t();
            return _process;
        }

        bool operator==(struct _mem_process_t _process)
        {
            return (bool)compare(_process);
        }

    };

    class process_list_t : public mem_process_list_t
    {
        public:
        mem_process_t  at      (mem_size_t pos) { return mem_process_list_at(this, pos); }
        mem_bool_t     is_valid() { return mem_process_list_is_valid(this); }
        mem_size_t     length  () { return mem_process_list_length(this); }
        mem_process_t* buffer  () { return mem_process_list_buffer(this); }
        mem_size_t     size    () { return mem_process_list_size(this); }
        mem_void_t     resize  (mem_size_t _size) { return mem_process_list_resize(this, _size); }
        mem_void_t     append  (mem_process_t process) { return mem_process_list_append(this, process); }

        public:
        process_list_t() { *(struct _mem_process_list_t*)this = mem_process_list_init(); }
        process_list_t(struct _mem_process_list_t _proc_list) { *(struct _mem_process_list_t*)this = _proc_list; }
        ~process_list_t() { /*mem_process_list_free(this);*/ }

        process_list_t operator=(struct _mem_process_list_t _proc_list)
        {
            this->~process_list_t();
            return process_list_t(_proc_list);
        }

        mem_process_t operator[](mem_size_t pos)
        {
            return at(pos);
        }
    };

    class module_t : public mem_module_t
    {
        public:
        mem_bool_t is_valid() { return mem_module_is_valid(this); }
        mem_bool_t compare (struct _mem_module_t _mod) { return mem_module_compare(this, _mod); }

        public:
        module_t() { *(struct _mem_module_t*)this = mem_module_init(); }
        module_t(struct _mem_module_t _mod) { *(struct _mem_module_t*)this = _mod; }
        ~module_t() { /*mem_module_free(this);*/ }

        module_t operator=(struct _mem_module_t _mod)
        {
            this->~module_t();
            return module_t(_mod);
        }

        bool operator==(struct _mem_module_t _mod)
        {
            return (bool)compare(_mod);
        }
    };

    class module_list_t : public mem_module_list_t
    {
        public:
        mem_module_t  at      (mem_size_t pos) { return mem_module_list_at(this, pos); }
        mem_bool_t    is_valid() { return mem_module_list_is_valid(this); }
        mem_size_t    length  () { return mem_module_list_length(this); }
        mem_module_t* buffer  () { return mem_module_list_buffer(this); }
        mem_size_t    size    () { return mem_module_list_size(this); }
        mem_void_t    resize  (mem_size_t _size) { return mem_module_list_resize(this, _size); }
        mem_void_t    append  (mem_module_t process) { return mem_module_list_append(this, process); }

        public:
        module_list_t() { *(struct _mem_module_list_t*)this = mem_module_list_init(); }
        module_list_t(struct _mem_module_list_t _mod_list) { *(struct _mem_module_list_t*)this = _mod_list; }
        ~module_list_t() { /*mem_module_list_free(this);*/ }

        module_list_t operator=(struct _mem_module_list_t _mod_list)
        {
            this->~module_list_t();
            return module_list_t(_mod_list);
        }

        mem_module_t operator[](mem_size_t pos)
        {
            return at(pos);
        }
        
    };

    class page_t : public mem_page_t
    {
        public:
        mem_bool_t is_valid() { return mem_page_is_valid(this); }

        public:
        page_t()  { *(struct _mem_page_t*)this = mem_page_init(); }
        page_t(struct _mem_page_t _page) { *(struct _mem_page_t*)this = _page; }
        ~page_t() {  }
    };

    class alloc_t : public mem_alloc_t
    {
        public:
        mem_bool_t is_valid() { return mem_alloc_is_valid(this); }

        public:

        alloc_t() { *(struct _mem_alloc_t*)this = mem_alloc_init(); }
        alloc_t(struct _mem_alloc_t _alloc) { *(struct _mem_alloc_t*)this = _alloc; }
        ~alloc_t() {  }

        alloc_t operator=(struct _mem_alloc_t _alloc)
        {
            this->~alloc_t();
            return alloc_t(_alloc);
        }
    };

    class lib_t : public mem_lib_t
    {
        public:
        mem_bool_t is_valid() { return mem_lib_is_valid(this); }

        public:
        lib_t() { *(struct _mem_lib_t*)this = mem_lib_init(); }
        lib_t(string_t path, int_t mode) { *(struct _mem_lib_t*)this = mem_lib_new(path, mode); }
        lib_t(struct _mem_lib_t _lib) { *(struct _mem_lib_t*)this = _lib; }
        ~lib_t() { /*mem_lib_free(this);*/ }

        lib_t operator=(struct _mem_lib_t _lib)
        {
            this->~lib_t();
            return lib_t(_lib);
        }
    };

    class vtable_t : public _mem_vtable_t
    {
        public:
        bool_t     is_valid() { return mem_vtable_is_valid(this); }
        mem_bool_t hook(mem_size_t index, mem_voidptr_t dst) { return mem_vtable_hook(this, index, dst); }
        mem_bool_t restore(mem_size_t index) { return mem_vtable_restore(this, index); }

        public:
        vtable_t() { *(struct _mem_vtable_t*)this = mem_vtable_init(); }
        vtable_t(mem_voidptr_t* p_vtable, mem_size_t size) { *(struct _mem_vtable_t*)this = mem_vtable_new(p_vtable, size); }
        ~vtable_t() { /*mem_vtable_free(this);*/ }
    };

    typedef _mem_detour_t detour_t;

    //libmem

    inline string_t parse_mask(string_t mask) { return mem_parse_mask(mask); }
    inline uintptr_t get_page_size() { return mem_get_page_size(); }

    namespace ex
    {
        inline pid_t          get_pid(string_t process_name) { return mem_ex_get_pid(process_name); }
        inline string_t       get_process_name(pid_t pid) { return mem_ex_get_process_name(pid); }
        inline process_t      get_process(pid_t pid) { return mem_ex_get_process(pid); }
        inline process_t      get_process(string_t process_name) { return mem_ex_get_process(mem_ex_get_pid(process_name)); }
        inline process_list_t get_process_list() { return mem_ex_get_process_list(); }
        inline module_t       get_module(process_t process, string_t module_name) { return mem_ex_get_module(process, module_name); }
        inline module_list_t  get_module_list(process_t process) { return mem_ex_get_module_list(process); }
        inline page_t         get_page(process_t process, mem_voidptr_t src) { return page_t(mem_ex_get_page(process, src)); }
        inline bool_t         is_process_running(process_t process) { return mem_ex_is_process_running(process); }
        inline int_t          read(process_t process, voidptr_t src, voidptr_t dst, size_t size) { return mem_ex_read(process, src, dst, size); }
        template<typename type_t>
        inline type_t         read(process_t process, voidptr_t src) { type_t data; mem_ex_read(process, src, &data, sizeof(data)); return data; }
        inline int_t          write(process_t process, voidptr_t src, voidptr_t data, size_t size) { return mem_ex_write(process, src, data, size); }
        template<typename type_t>
        inline int_t          write(process_t process, voidptr_t dst, type_t src) { return mem_ex_write(process, dst, src, sizeof(src)); }
        inline int_t          set(process_t process, voidptr_t dst, byte_t byte, size_t size) { return mem_ex_set(process, dst, byte, size); }
        inline voidptr_t      syscall(process_t process, int_t syscall_n, voidptr_t arg0, voidptr_t arg1, voidptr_t arg2, voidptr_t arg3, voidptr_t arg4, voidptr_t arg5) { return mem_ex_syscall(process, syscall_n, arg0, arg1, arg2, arg3, arg4, arg5); }
        inline int_t          protect(process_t process, voidptr_t src, size_t size, prot_t protection) { return mem_ex_protect(process, src, size, protection); }
        inline voidptr_t      allocate(process_t process, size_t size, prot_t protection) { return mem_ex_allocate(process, size, protection); }
        inline int_t          deallocate(process_t process, voidptr_t src, size_t size) { return mem_ex_deallocate(process, src, size); }
        inline voidptr_t      scan(process_t process, byte_t* data, voidptr_t begin, voidptr_t end, size_t size) { return mem_ex_scan(process, data, begin, end, size); }
        inline voidptr_t      pattern_scan(process_t process, byte_t* pattern, string_t mask, voidptr_t begin, voidptr_t end) { return mem_ex_pattern_scan(process, pattern, mask, begin, end); }
        inline voidptr_t      pattern_scan(process_t process, byte_t* pattern, string_t mask, module_t mod) { return mem_ex_pattern_scan(process, pattern, mask, mod.base, mod.end); }
        inline int_t          detour(process_t process, voidptr_t src, voidptr_t dst, size_t size, detour_t method, byte_t** stolen_bytes = NULL) { return mem_ex_detour(process, src, dst, size, method, stolen_bytes); }
        inline voidptr_t      detour_trampoline(process_t process, voidptr_t src, voidptr_t dst, size_t size, detour_t method, byte_t** stolen_bytes = NULL) { return mem_ex_detour_trampoline(process, src, dst, size, method, stolen_bytes); }
        inline void_t         detour_restore(process_t process, voidptr_t src, byte_t* stolen_bytes, size_t size) { return mem_ex_detour_restore(process, src, stolen_bytes, size); }
        inline module_t       load_library(process_t process, lib_t lib) { return mem_ex_load_library(process, lib); }
        inline voidptr_t      get_symbol(module_t mod, const char* symbol) { return mem_ex_get_symbol(mod, symbol); }
    }

    namespace in
    {
        inline pid_t         get_pid() { return mem_in_get_pid(); }
        inline process_t     get_process() { return mem_in_get_process(); }
        inline string_t      get_process_name() { return mem_in_get_process_name(); }
        inline module_t      get_module(string_t module_name) { return mem_in_get_module(module_name); }
        inline module_list_t get_module_list() { return mem_in_get_module_list(); }
        inline page_t        get_page(mem_voidptr_t src) { return page_t(mem_in_get_page(src)); }
        inline voidptr_t     pattern_scan(byte_t* pattern, string_t mask, voidptr_t begin, voidptr_t end) { return mem_in_pattern_scan(pattern, mask, begin, end); }
        inline voidptr_t     pattern_scan(byte_t* pattern, string_t mask, module_t  mod) { return mem_in_pattern_scan(pattern, mask, mod.base, mod.end); }
        inline void_t        read(voidptr_t src, voidptr_t dst, size_t size) { return mem_in_read(src, dst, size); }
        template<typename type_t>
        inline type_t        read(voidptr_t src) { type_t data; mem_in_read(src, &data, sizeof(data)); return data; }
        inline void_t        write(voidptr_t dst, voidptr_t src, size_t size) { return mem_in_write(dst, src, size); }
        template<typename type_t>
        inline void_t        write(voidptr_t dst, type_t src) { return mem_in_write(dst, src, sizeof(src)); }
        inline void_t        set(voidptr_t src, byte_t byte, size_t size) { return mem_in_set(src, byte, size); }
        inline voidptr_t     syscall(int_t syscall_n, voidptr_t arg0, voidptr_t arg1, voidptr_t arg2, voidptr_t arg3, voidptr_t arg4, voidptr_t arg5) { return mem_in_syscall(syscall_n, arg0, arg1, arg2, arg3, arg4, arg5); }
        inline int_t         protect(voidptr_t src, size_t size, prot_t protection) { return mem_in_protect(src, size, protection); }
        inline voidptr_t     allocate(size_t size, prot_t protection) { return mem_in_allocate(size, protection); }
        inline void_t        deallocate(voidptr_t src, size_t size) { return mem_in_deallocate(src, size); }
        inline bool_t        compare(voidptr_t pdata1, voidptr_t pdata2, size_t size) { return mem_in_compare(pdata1, pdata2, size); }
        inline voidptr_t     scan(voidptr_t data, voidptr_t begin, voidptr_t end, size_t size) { return mem_in_scan(data, begin, end, size); }
        inline size_t        detour_length(detour_t method) { return mem_in_detour_length(method); }
        inline int_t         detour(voidptr_t src, voidptr_t dst, size_t size, detour_t method, byte_t** stolen_bytes = NULL) { return mem_in_detour(src, dst, size, method, stolen_bytes); }
        inline voidptr_t     detour_trampoline(voidptr_t src, voidptr_t dst, size_t size, detour_t method, byte_t** stolen_bytes = NULL) { return mem_in_detour_trampoline(src, dst, size, method, stolen_bytes); }
        inline void_t        detour_restore(voidptr_t src, byte_t* stolen_bytes, size_t size) { return mem_in_detour_restore(src, stolen_bytes, size); }
        inline module_t      load_library(lib_t lib) { return mem_in_load_library(lib); }
        inline void_t        unload_library(module_t mod) { return mem_in_unload_library(mod); }
        inline voidptr_t     get_symbol(module_t mod, const char* symbol) { return mem_in_get_symbol(mod, symbol); }
    }
}
#endif
#endif