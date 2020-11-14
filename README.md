<p align="center">
  <a href="https://github.com/rdbo/libmem"><img src="https://github.com/rdbo/libmem/blob/master/img/logo.png"/></a>
</p>  

# Usage
Copy the 'libmem' folder to your project directory.  
Make sure to compile 'libmem.c' along with your project.  

# Dependencies
Windows: Windows SDK  
Linux:   libdl (-ldl)  

# License
Read 'LICENSE'  

# Overview
```
//libmem

mem_parse_mask
mem_get_page_size

//ex
mem_ex_get_pid
mem_ex_get_process_name
mem_ex_get_process
mem_ex_get_process_list
mem_ex_get_module
mem_ex_get_module_list
mem_ex_get_page
mem_ex_is_process_running
mem_ex_read
mem_ex_write
mem_ex_set
mem_ex_syscall
mem_ex_protect
mem_ex_allocate
mem_ex_deallocate
mem_ex_scan
mem_ex_pattern_scan
mem_ex_detour
mem_ex_detour_trampoline
mem_ex_detour_restore
mem_ex_load_library
mem_ex_get_symbol

//in

mem_in_get_pid
mem_in_get_process
mem_in_get_process_name
mem_in_get_module
mem_in_get_module_list
mem_in_get_page
mem_in_pattern_scan
mem_in_read
mem_in_write
mem_in_set
mem_in_syscall
mem_in_protect
mem_in_allocate
mem_in_deallocate
mem_in_compare
mem_in_scan
mem_in_detour_length
mem_in_detour
mem_in_detour_trampoline
mem_in_detour_restore
mem_in_load_library
mem_in_unload_library
mem_in_get_symbol
```

# Projects
Made with libmem:  
<a href="https://github.com/rdbo/x-inject">X-Inject - Library injector for Windows and Linux</a>  
<a href="https://github.com/karliky/Crazymem">Crazymem - NodeJS Memory Library</a>  

# TODO
. Add support for ARM  
