# libmem by rdbo - Documentation 
  
**ALL LIBMEM FUNCTIONS ARE DOCUMENTS ON `libmem/libmem.c`. Make sure to read the comments**  
  
# Overview
  
Functions that start with `mem_in_*` or `mem::in::*` are functions that interact with the caller program.  
Functions that start with `mem_ex_*` or `mem::ex::*` are functions that interact with an external program. They generally require a `mem_process_t` or `mem_pid_t` to be passed as parameter, as they can be used to identify the target process.  

# Description
  
Summary of each function in libmem. See `libmem/libmem.c` comments for more detailed descriptions and important information.  
  
```
//mem_in
mem_in_read_file                //Reads the data of a file
mem_in_get_pid                  //Gets the PID of the caller process
mem_in_get_process_name         //Gets the name of the caller process
mem_in_get_process_path         //Gets the path of the caller process
mem_in_get_arch                 //Gets the architecture of the caller process
mem_in_get_process              //Gets the process handle (mem_process_t) of the caller process
mem_in_get_module               //Gets a module handle from the caller process
mem_in_get_module_name          //Gets the module name of a module from the caller process
mem_in_get_module_path          //Gets the module path of a module from the caller process
mem_in_get_module_list          //Gets the module list of the caller process
mem_in_get_page                 //Gets information about a page of the caller process
mem_in_read                     //Reads memory from the caller process
mem_in_write                    //Writes memory to the caller process
mem_in_set                      //Sets a memory region to a specified byte in the caller process
mem_in_syscall                  //Runs a syscall in the caller process
mem_in_protect                  //Changes the protection flags of a memory region of the caller process
mem_in_allocate                 //Allocates memory in the caller process
mem_in_deallocate               //Deallocates memory in the caller process
mem_in_scan                     //Scans for a byte pattern in the caller process
mem_in_pattern_scan             //Scans for a byte pattern and checks a byte mask in the caller process
mem_in_signature_scan           //Scans for a byte signature in the caller process
mem_in_payload_size             //Gets the size of a payload
mem_in_detour_size              //Gets the size of a detour method
mem_in_detour                   //Detours code in the caller process
mem_in_detour_trampoline        //Detours code and saves the original code in a gateway in the caller process
mem_in_detour_restore           //Restores detoured code in the caller process
mem_in_load_module              //Loads a module in the caller process
mem_in_unload_module            //Unloads a module in the caller process
mem_in_get_symbol               //Gets a symbol from a module in the caller process

//mem_ex
mem_ex_get_pid                  //Gets the PID of a process
mem_ex_get_process_name         //Gets the name of a process
mem_ex_get_process_path         //Gets the path of a process
mem_ex_get_system_arch          //Gets the system architecture
mem_ex_get_arch                 //Gets the architecture of a process
mem_ex_get_process              //Gets the process handle (mem_process_t) of a process
mem_ex_get_process_list         //Gets the process list
mem_ex_get_module               //Gets a module in a process
mem_ex_get_module_name          //Gets the name of a module in a process
mem_ex_get_module_path          //Gets the path of a module in a process
mem_ex_get_module_list          //Gets the module list of a process
mem_ex_get_page                 //Gets information about a page in a process
mem_ex_is_process_running       //Checks if a process is running
mem_ex_read                     //Reads memory from a process
mem_ex_write                    //Writes memory to a process
mem_ex_set                      //Sets a memory region to a specified byte in a process
mem_ex_syscall                  //Runs a syscall in a process
mem_ex_protect                  //Changes the protection flags of a memory region in a process
mem_ex_allocate                 //Allocates memory in a process
mem_ex_deallocate               //Deallocates memory in a process
mem_ex_scan                     //Scans for a byte pattern in a process
mem_ex_pattern_scan             //Scans for a byte pattern and checks a byte mask in a process
mem_ex_signature_scan           //Scans for a byte signature in a process
mem_in_detour                   //Detours code in a process
mem_ex_load_module              //Loads a module in a process
mem_ex_unload_module            //Unloads a module in a process
mem_ex_get_symbol               //Gets a symbol from a module in a process
```  
