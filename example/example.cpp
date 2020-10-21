#include "../libmem/libmem.hpp"


#if defined(MEM_WIN)     //Windows specific
#define PROCESS_NAME MEM_STR("example.exe")
#define PROTECTION PAGE_EXECUTE_READWRITE
#if defined(MEM_86) //32 bit only
#define CALL __cdecl
#define HOOK_SIZE 12
#elif defined(MEM_64) //64 bit only
#define CALL __fastcall
#define HOOK_SIZE 12
#endif
#elif defined(MEM_LINUX) //Linux specific
#define PROCESS_NAME MEM_STR("example.o")
#define PROTECTION PROT_EXEC | PROT_READ | PROT_WRITE
#define CALL
#if defined(MEM_86)   //32 bit only
#define HOOK_SIZE 12
#elif defined(MEM_64) //64 bit only
#define HOOK_SIZE 12
#endif
#endif

#if defined(MEM_UCS)    //Unicode character set
#define print(...) wprintf(MEM_STR("\n") __VA_ARGS__)
#elif defined(MEM_MBCS) //Multibyte character set
#define print(...) printf(MEM_STR("\n") __VA_ARGS__)
#endif

#define tprint(...) print("    "  __VA_ARGS__)
#define HOOK_METHOD MEM_DT_M0

bool CALL function(bool ret_value);    //Function that will be hooked on 'Internal tests'
bool CALL hk_function(bool ret_value); //Hook of function
typedef bool(CALL* t_function)(bool); //Template of the hooked function
t_function o_function;                /*Gateway to run the original code of the
									  hooked function and restore the normal execution
									  */

int main()
{
	//External
	print("External tests:");

	//-- Get Process ID
	mem_string_t process_name = mem_string_new(PROCESS_NAME);
	mem_pid_t pid_ex = mem_ex_get_pid(process_name);
	tprint("PID:                %i", pid_ex);

	//-- Get Process Information
	mem_process_t process_ex = mem_ex_get_process(pid_ex);
	tprint("Process Name:       %s", mem_string_c_str(&process_ex.name));
	tprint("Process ID:         %i", process_ex.pid);

	//-- Get Process Module
	mem_module_t process_mod_ex = mem_ex_get_module(process_ex, process_name);
	tprint("Module Name:        %s", mem_string_c_str(&process_mod_ex.name));
	tprint("Module Path:        %s", mem_string_c_str(&process_mod_ex.path));
	tprint("Module Base:        %p", process_mod_ex.base);
	tprint("Module Size:        %p", (mem_voidptr_t)process_mod_ex.size);
	tprint("Module End:         %p", process_mod_ex.end);

	//-- Allocate Memory
	mem_voidptr_t alloc_ex = mem_ex_allocate(process_ex, sizeof(int), PROTECTION);
	tprint("Allocated memory:   %p", alloc_ex);

	//-- Writing to Memory

	int write_buffer_ex = 10;
	mem_ex_write(process_ex, alloc_ex, &write_buffer_ex, sizeof(write_buffer_ex));
	tprint("Wrote '%i' to:      %p", write_buffer_ex, alloc_ex);

	//-- Reading from Memory
	int read_buffer_ex = 0;
	mem_ex_read(process_ex, alloc_ex, &read_buffer_ex, sizeof(read_buffer_ex));
	tprint("Read  '%i' from:    %p", read_buffer_ex, alloc_ex);

	//-- Pattern Scanning
	mem_byte_t pattern[] = { (mem_byte_t)0x10, (mem_byte_t)0x20, (mem_byte_t)0x0, (mem_byte_t)0x30, (mem_byte_t)0x40, (mem_byte_t)0x50,(mem_byte_t)0x60, (mem_byte_t)0x70, (mem_byte_t)0x80, (mem_byte_t)0x90, (mem_byte_t)0xA0, (mem_byte_t)0x00, (mem_byte_t)0xB0 };
	mem_string_t mask = mem_string_new(MEM_STR("xx?xxxxxxxx?x"));
	mem_voidptr_t scan = mem_ex_pattern_scan(process_ex, pattern, mask, (mem_voidptr_t)((mem_uintptr_t)pattern - 0x10), (mem_voidptr_t)((mem_uintptr_t)pattern + 0x10));
	tprint("Pattern Scan:       %p", scan);
	tprint(" (expected result): %p", (mem_voidptr_t)pattern);

	//-- Get Page Information
	mem_page_t page_ex = mem_ex_get_page(process_ex, process_mod_ex.base);
	tprint("Page Base:          %p", page_ex.base);
	tprint("Page Size:          %p", (mem_voidptr_t)page_ex.size);
	tprint("Page End:           %p", page_ex.end);
	tprint("Page Protection:    %i", (mem_int_t)page_ex.protection);
	tprint("Page Flags:         %i", (mem_int_t)page_ex.flags);

	print();
	print("====================");
	print();

	//====================

	//Internal

	print("Internal tests:");

	//-- Get Process ID
	mem_pid_t pid_in = mem_in_get_pid();
	tprint("PID:                %i", pid_in);

	//-- Get Process Information
	mem_process_t process_in = mem_in_get_process();
	tprint("Process Name:       %s", mem_string_c_str(&process_in.name));
	tprint("Process ID:         %i", process_in.pid);

	//-- Get Process Module
	mem_module_t process_mod_in = mem_in_get_module(process_name);
	tprint("Module Name:        %s", mem_string_c_str(&process_mod_in.name));
	tprint("Module Path:        %s", mem_string_c_str(&process_mod_in.path));
	tprint("Module Base:        %p", process_mod_in.base);
	tprint("Module Size:        %p", (mem_voidptr_t)process_mod_in.size);
	tprint("Module End:         %p", process_mod_in.end);

	//-- Allocate Memory

	mem_voidptr_t alloc_in = mem_in_allocate(sizeof(int), PROTECTION);
	tprint("Allocated memory:   %p", alloc_in);

	//-- Write to Memory
	int write_buffer_in = 1337;
	mem_in_write(alloc_in, &write_buffer_in, sizeof(write_buffer_in));
	tprint("Wrote '%i' to:    %p", write_buffer_in, alloc_in);

	//-- Read from Memory

	int read_buffer_in = 0;
	mem_in_read(alloc_in, &read_buffer_in, sizeof(read_buffer_in));
	tprint("Read  '%i' from:  %p", read_buffer_in, alloc_in);

	//-- Pattern Scanning

	mem_voidptr_t scan_in = mem_in_pattern_scan(pattern, mask, (mem_voidptr_t)((mem_uintptr_t)pattern - 0x10), (mem_voidptr_t)((mem_uintptr_t)pattern + 0x10));
	tprint("Pattern Scan:       %p", scan_in);
	tprint(" (expected result): %p", (mem_voidptr_t)pattern);

	//-- Get Page Information
	mem_page_t page_in = mem_in_get_page(process_mod_in.base);
	tprint("Page Base:          %p", page_in.base);
	tprint("Page Size:          %p", (mem_voidptr_t)page_in.size);
	tprint("Page End:           %p", page_in.end);
	tprint("Page Protection:    %i", (mem_int_t)page_in.protection);
	tprint("Page Flags:         %i", (mem_int_t)page_in.flags);

	/*-- Hook 'function' (the overwritten bytes size can vary on each compilation, so it's commented).
	o_function = (t_function)mem_in_detour_trampoline(
	(mem_voidptr_t)function,    //target
	(mem_voidptr_t)hk_function, //detour
	HOOK_SIZE,                  //size of the overwritten ASM instructions
	HOOK_METHOD,                //hooking method (check mem_detour_int_t)
	NULL                        //  stolen bytes (to restore the original bytes in the future).
	//  Use NULL to ignore

	);

	function(false);
	*/


	//Free memory
	mem_module_free(&process_mod_in);
	mem_module_free(&process_mod_ex);
	mem_process_free(&process_in);
	mem_process_free(&process_ex);
	mem_string_free(&mask);
	mem_string_free(&process_name);

	//Exit
	print();
	print("Press [ENTER] to exit...");
	getchar();
	return 0;
}

bool CALL function(bool ret_value)
{
	/* This function will be hooked and will execute 'hk_function' instead;
	After that, it will run this function and restore the original execution flow.
	*/

	return ret_value;
}

bool CALL hk_function(bool ret_value)
{
	tprint("Hooked successfully!");
	ret_value = true;
	return o_function(ret_value);
}