# libmem by rdbo - Documentation 

**DISCLAIMER**: This documentation does NOT cover 100% of the libmem, but it contains all the important stuff you need to know in order to use it properly.  
  
# 1. Understanding defines and macros  
  
*MEM_WIN*:   defined when the code is compiled on Windows  
*MEM_LINUX*: defined when the code is compiled on Linux  
*MEM_86*:    defined when the code is compiled as x86_32 (32 bits)  
*MEM_64*:    defined when the code is compiled as x86_64 (64 bits)  
*MEM_UCS*:   defined when the code is compiled with unicode character set (Windows only)  
*MEM_MBCS*:  defined when the code is compiled with multibyte character set.  
*MEM_CPP*:   defined when the code is written in C++  
*MEM_C*:     defined when the code is written in C  
  
*MEM_STR(str)*: automatically choose between Unicode or Multibyte string.  
*MEM_STR_CMP(str1, str2)*: compare 2 strings (adapted for Unicode and Multibyte).  
*MEM_STR_N_CMP(str1, str2, n)*: compare N characters of 2 strings (adapted for Unicode and Multibyte).  
*MEM_STR_LEN(str)*: get length of string.  
  
*MEM_THISCALL(obj, func, ...)*: simulates a 'thiscall' for a C structure that has a function pointer.  
  
*MEM_BAD_RETURN*: used for error checking and it is defined as -1.  
  
# 2. Understanding types  
  
Libmem has some base types to make coding with it easier, like:  
  
**mem_bool_t**:  
	a bool type for C. True is 'mem_true' and False is 'mem_false'.  
	```
	typedef enum { mem_false = 0, mem_true = 1 } mem_bool_t;
	```  
  
**mem_string_t**:  
	a string type that contains multiple helper functions and is very used in libmem.  
  
As this project supports multiple platforms (currently Windows and Linux), I had to create generic types that match both systems' behaviours:  
  
**mem_pid_t**:  
	holds a process id. It is used to grab information about a process (check *mem_process_t*).  
	```
	#if defined(MEM_WIN)
	typedef DWORD mem_pid_t;
	#elif defined(MEM_LINUX)
	typedef mem_int32_t mem_pid_t;
	#endif
	```

**mem_process_t**:  
	contains information about a process. It is used to manipulate that process through mem_ex_* functions. Can be gotten through '*mem_ex_get_process*', '*mem_in_get_process*' (for the calling process), or manual iterations through the process list (check *mem_process_list_t*).  
	```
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
	```  
  
**mem_process_list_t**:  
	contains a list of all processes (*mem_process_t*). It can be used to do manual iterations through every process. It has to be gotten through '*mem_ex_get_process_list*'.  
	```
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
	```  
  
**mem_module_t**:  
	contains information about a module. Modules are loaded into the process memory (like dynamic libraries) or in this case, can even be the process itself. Can be gotten through '*mem_ex_get_module*', '*mem_in_get_module*' (for the calling process), or manual iterations through the module list (check *mem_module_list_t*).  
	```
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
	```  
  
**mem_module_list_t**:  
	contains a list of all loaded modules of a process. It can be used to do manual iterations through each module of a process. It can be gotten through '*mem_ex_get_module_list*' or '*mem_in_get_module_list*' (for the calling process).  
	```
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
	```  
  
**mem_page_t**:  
	contains information about a page. Can be gotten through '*mem_ex_get_page*' or '*mem_in_get_page*' (for the calling process).  
	```
	typedef struct _mem_page_t
	{
	    mem_bool_t       is_initialized;
	    mem_voidptr_t    base;
	    mem_uintptr_t    size;
	    mem_voidptr_t    end;
	    mem_flags_t      flags;
	    mem_prot_t       protection;
	    mem_bool_t(* is_valid)(struct _mem_page_t* p_page);
	}mem_page_t;
	```  
  
**mem_prot_t**:  
	stores a page protection flag. This is OS-specific. On Linux, you have '*PROT_READ*', '*PROT_WRITE*', '*PROT_EXEC*', ... (check <a href="https://man7.org/linux/man-pages/man2/mprotect.2.html#DESCRIPTION">the man page</a> for more); On Windows you have 'PAGE_EXECUTE', 'PAGE_EXECUTE_READ', 'PAGE_EXECUTE_WRITECOPY', ... (check <a href="https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants#constants">MS Docs</a> for more).  
	```
	#if defined(MEM_WIN)
	typedef DWORD mem_prot_t;
	#elif defined(MEM_LINUX)
	typedef mem_int32_t mem_prot_t;
	#endif
	```  

**mem_lib_t**:  
	stores information about a library that will be loaded.  
	```
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
	```  
  
**ATTENTION!!**: Some types require initialization, either through '*mem_\<type_here\>_init*' or '*mem_\<type_here\>_new(params)*'. Example:  
`mem_string_t str = mem_string_new(MEM_STR("hello there"));`  
A lot of the types in libmem use 'malloc', so you'll have to manually free these types. To free their memory and avoid memory leaks, use the following template: '*mem_\<type_here\>_free(p_data)*'. Examples:  
`mem_process_free(&process);`  
`mem_string_free(&str);`  
  
  
# 3. Understanding functions  
  
Libmem contains a whole set of functions that allow you to interact with other processes (ex - as in external), and interact with the caller process (in - as in internal).  
  
# 3.1 - Global (External/Internal):  
**mem_parse_mask(mask)**: Parses the mask '*mask*' to turn it into a uniform mask (a mask where 'x' = known byte and '?' = unknown byte).  
**mem_get_page_size()**:  Gets the system page size.  
  
# 3.2 - External (mem_ex\*)  
**mem_ex_get_pid(process_name)**: Iterates through the process list and returns the first process ID that is named '*process_name*'. Returns a '*mem_pid_t*'.  
**mem_ex_get_process_name(pid)**: Gets the process name of '*pid*'. Returns a '*mem_string_t*'.  
**mem_ex_get_process(pid)**: Gets the process information of the process that has the ID '*pid*'. Returns a '*mem_process_t*'.  
**mem_ex_get_process_list()**: Gets a list of the currently running processes. Returns a *mem_process_list_t*.  
**mem_ex_get_module(process, module_name)**: Gets information about the first loaded module named '*module_name*' in '*process*'. Returns a '*mem_module_t*'.  
**mem_ex_get_module_list(process)**: Gets a list of all the loaded modules in '*process*'. Returns a '*mem_module_list_t*'.  
**mem_ex_get_page(process, src)**: Gets the page information at '*src*' address in '*process*'. Returns a '*mem_page_t*'.  
**mem_ex_is_process_running(process)**: Checks if a process is running. Returns either '*mem_true*' or '*mem_false*' (type '*mem_bool_t*').  
**mem_ex_read(process, src, dst, size)**: Reads memory of size '*size*' at '*src*' from '*process*' and stores it in '*dst*'.  
**mem_ex_write(process, dst, src, size)**: Writes memory of size '*size*' from '*src*' to '*dst*' at '*process*'.  
**mem_ex_set(process, dst, byte, size)**: Sets '*size*' bytes of '*dst*' as '*byte*' at '*process*'. Similar to 'memset'.  
**mem_ex_syscall(process, syscall_n, arg0, arg1, arg2, arg3, arg4, arg5)**: Runs a syscall at '*process*' with the arguments '*arg0*' to '*arg5*'. Returns the return of the syscall.  
**mem_ex_protect(process, src, size, protection)**: Sets the protection of '*src*' as '*protection*' with size of '*size*' at '*process*'. Returns MEM_BAD_RETURN on error.  
**mem_ex_allocate(process, size, protection)**: Allocates memory of size '*size*' with the protection of '*protection*' at '*process*'. Returns the adress of the allocation or MEM_BAD_RETURN on error.  
**mem_ex_deallocate(process, src, size)**: Deallocates memory of size '*size*' at '*src*' in '*process*'. Returns MEM_BAD_RETURN on error.  
**mem_ex_scan(process, data, begin, end, size)**: Scan for '*data*' of size '*size*' from '*begin*' to '*end*' in '*process*'. Returns the address of the found data, or MEM_BAD_RETURN if the data was not found.  
**mem_ex_pattern_scan(process, pattern, mask, begin, end)**: Scans for '*pattern*' from '*begin*' to '*end*' in '*process*'. It uses '*mask*' to define which bytes are known 'x' or unknown '?'. Returns the address of the found pattern, or MEM_BAD_RETURN if the pattern was not found.  
**mem_ex_detour(process, src, dst, size, method, stolen_bytes)**: Detours '*src*' to '*dst*' using the detour method '*method*' on process. Also, it stores the overwritten bytes with size '*size*' to '*stolen_bytes*' (if stolen_bytes is not null). Returns MEM_BAD_RETURN on error.  
**mem_ex_detour_trampoline(process, src, dst, size, method, stolen_bytes)**: Does the same as '*mem_ex_detour*', but returns a gateway that can be used to restore the execution of the target process. Returns MEM_BAD_RETURN on error.  
**mem_ex_detour_restore(process, src, stolen_bytes, size)**: Restores the overwritten bytes of a detour.  
**mem_ex_load_library(process, lib)**: Loads the shared/dynamic library '*lib*' into '*process*'. Returns MEM_BAD_RETURN on error.  
**mem_ex_get_symbol(mod, symbol)**: Loads '*mod*' into the caller process and searches for the symbol '*symbol*'. Returns the address of the symbol in the target process or MEM_BAD_RETURN if the symbol was not found.  

# 3.3 - Internal (mem_in\*)  
**mem_in_get_pid()**: Returns the process ID of the caller process as '*mem_pid_t*'.  
**mem_in_get_process()**: Returns the process information of the caller process as '*mem_process_t*'.  
**mem_in_get_process_name()**: Returns the process name of the caller process as '*mem_string_t*'.  
**mem_in_get_module(mem_string_t module_name)**: Returns the module information of the first loaded module named '*module_name*' of the caller process as '*mem_module_t*'.  
**mem_in_get_module_list()**: Returns the loaded module list of the caller process as '*mem_module_list*'.  
**mem_in_get_page(src)**: Returns the page information at '*src*' in the caller process as '*mem_page_t*'.  
**mem_in_pattern_scan(pattern, mem_string_t mask, mem_voidptr_t begin, mem_voidptr_t end)**: Scans for '*pattern*' from '*begin*' to '*end*' in the caller process. It uses '*mask*' to define which bytes are known 'x' or unknown '?'. Returns the address of the found pattern, or MEM_BAD_RETURN if the pattern was not found.  
**mem_in_read(src, dst, size)**: Reads memory of size '*size*' at '*src*' and stores it in '*dst*' in the caller process.  
**mem_in_write(dst, src, size)**: Writes memory of size '*size*' from '*src*' to '*dst*' in the caller process.  
**mem_in_set(src, byte, size)**: Sets '*size*' bytes of '*src*' to '*byte*' in the caller process.  
**mem_in_syscall(syscall_n, arg0, arg1, arg2, arg3, arg5)**: Runs a syscall of number '*syscall_n*' in the caller process with the arguments '*arg0*' to '*arg5*'. Returns the return of the syscall.  
**mem_in_protect(mem_voidptr_t src, mem_size_t size, mem_prot_t protection)**: Protects '*size*' bytes of '*src*' with the flag '*protection*' in the caller process.  
**mem_in_allocate(mem_size_t size, mem_prot_t protection)**: Allocates '*size*' bytes with the protection '*protection*' in the caller process. Returns the address of the allocation or MEM_BAD_RETURN on error.  
**mem_in_deallocate(mem_voidptr_t src, mem_size_t size)**: Deallocates '*size*' bytes of '*src*' in the caller process.  
**mem_in_compare(mem_voidptr_t pdata1, mem_voidptr_t pdata2, mem_size_t size)**: Compares 2 buffers of size '*size*'. Returns *mem_true* if they match or *mem_false* if they don't.  
**mem_in_scan(data, begin, end, size)**: Scans the memory for '*data*' of size '*size*' from '*begin*' to '*end*' in the caller process. Returns the address of the data found or MEM_BAD_RETURN on error/if no data was found.  
**mem_in_detour_length(method)**: Gets the detour length of *method*.  
**mem_in_detour(src, dst, size, method, stolen_bytes)**: Detours '*src*' to '*dst*' using the detour method '*method*' in the caller process. Stores the overwritten bytes of size '*size*' in '*stolen_bytes*' (if not null).  
**mem_in_detour_trampoline(src, dst, size, method, stolen_bytes)**: Does the same as '*mem_in_detour*', but returns a gateway that can be used to restore the execution of the target process. Returns MEM_BAD_RETURN on error.  
**mem_in_detour_restore(src, stolen_bytes, size)**: Restores the overwritten bytes of a detour.  
**mem_in_load_library(mem_lib_t lib)**: Loads the library '*lib*' into the caller process.  
**mem_in_unload_library(mem_module_t mod)**: Unloads a loaded module '*mod*' from the caller process.  
**mem_in_get_symbol(mem_module_t mod, const char* symbol)**: Gets the symbol '*symbol*' of '*module*'. Returns the address of the symbol, or MEM_BAD_RETURN on error/if the symbol does not exist.  