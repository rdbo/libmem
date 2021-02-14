![libmem-logo](img/logo.png)  
  
# 
# Usage
Copy the `libmem` folder to your project directory.  
Include `libmem/libmem.h` (C/C++) or `libmem/libmem.hpp` (C++) in your project.  
Compile `libmem/libmem.c` along with your project.  

# Dependencies
Windows: Windows SDK  
Linux:   libdl (-ldl)  

# License
Read `LICENSE`  
  
# Overview
```
//mem_in
mem_in_get_pid
mem_in_get_process_name
mem_in_get_process_path
mem_in_get_arch
mem_in_get_process
mem_in_get_module
mem_in_get_module_name
mem_in_get_module_path
mem_in_get_module_list
mem_in_get_page
mem_in_read
mem_in_write
mem_in_set
mem_in_syscall
mem_in_protect
mem_in_allocate
mem_in_deallocate
mem_in_scan
mem_in_pattern_scan
mem_in_detour_size
mem_in_payload_size
mem_in_detour
mem_in_detour_trampoline
mem_in_detour_restore
mem_in_load_module
mem_in_unload_module
mem_in_get_symbol

//mem_ex
mem_ex_get_pid
mem_ex_get_process_name
mem_ex_get_process_path
mem_ex_get_system_arch
mem_ex_get_arch
mem_ex_get_process
mem_ex_get_process_list
mem_ex_get_module
mem_ex_get_module_name
mem_ex_get_module_path
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
mem_ex_load_module
mem_ex_unload_module
mem_ex_get_symbol
```

# Projects
Made with libmem:  
- ![AssaultCube Multihack](https://github.com/rdbo/AssaultCube-Multihack)  
- ![X-Inject - GUI Library injector for Windows and Linux](https://github.com/rdbo/x-inject)  
- ![DirectX9 BaseHook](https://github.com/rdbo/DX9-BaseHook)
- ![DirectX11 BaseHook](https://github.com/rdbo/DX11-BaseHook)
- ![OpenGL BaseHook](https://github.com/rdbo/GL-BaseHook)
- ![Counter-Strike 1.6 BaseHook](https://github.com/rdbo/cstrike-basehook)
- ![Crazymem - NodeJS Memory Library](https://github.com/karliky/Crazymem)
