# libmem
Memory library written in C (Windows/Linux)  

# Usage
Copy the 'libmem' folder to your project directory.  
Make sure to compile 'libmem.c' along with your project.  

# Dependencies
Windows: Windows SDK  
Linux:   libdl ( -ldl )  

# License
Read 'LICENSE'  

# Overview
```
//libmem

mem_string_t  mem_parse_mask

//ex
mem_pid_t     mem_ex_get_pid
mem_string_t  mem_ex_get_process_name
mem_process_t mem_ex_get_process
mem_module_t  mem_ex_get_module
mem_bool_t    mem_ex_is_process_running
mem_int_t     mem_ex_read
mem_int_t     mem_ex_write
mem_int_t     mem_ex_set
mem_int_t     mem_ex_protect
mem_voidptr_t mem_ex_allocate
mem_int_t     mem_ex_deallocate
mem_voidptr_t mem_ex_scan
mem_voidptr_t mem_ex_pattern_scan
mem_int_t     mem_ex_detour
mem_voidptr_t mem_ex_detour_trampoline
mem_void_t    mem_ex_detour_restore
mem_int_t     mem_ex_load_library
mem_voidptr_t mem_ex_get_symbol

//in

mem_pid_t     mem_in_get_pid
mem_process_t mem_in_get_process
mem_string_t  mem_in_get_process_name
mem_module_t  mem_in_get_module
mem_voidptr_t mem_in_pattern_scan
mem_void_t    mem_in_read
mem_void_t    mem_in_write
mem_void_t    mem_in_set
mem_int_t     mem_in_protect
mem_voidptr_t mem_in_allocate
mem_void_t    mem_in_deallocate
mem_bool_t    mem_in_compare
mem_voidptr_t mem_in_scan
mem_size_t    mem_in_detour_length
mem_int_t     mem_in_detour
mem_voidptr_t mem_in_detour_trampoline
mem_void_t    mem_in_detour_restore
mem_module_t  mem_in_load_library
mem_voidptr_t mem_in_get_symbol
```

# Projects
Made with libmem:
```
WIP
```

# TODO
. Add support for ARM  
. Add documentation  
. Add examples/projects  
. Clean up code  
