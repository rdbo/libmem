#include "../libmem++/libmem.hpp"

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
	mem::pid_t pid_ex = mem::ex::get_pid(PROCESS_NAME);
	tprint("PID:                %i", pid_ex);

	//-- Get Process Information
	mem::process_t process_ex = mem::ex::get_process(pid_ex);
	tprint("Process Name:       %s", process_ex.name.c_str());
	tprint("Process ID:         %i", process_ex.pid);

	//-- Get Process Module
	mem::module_t process_mod_ex = mem::ex::get_module(process_ex, PROCESS_NAME);
	tprint("Module Name:        %s", process_mod_ex.name.c_str());
	tprint("Module Path:        %s", process_mod_ex.path.c_str());
	tprint("Module Base:        %p", process_mod_ex.base);
	tprint("Module Size:        %p", (mem::voidptr_t)process_mod_ex.size);
	tprint("Module End:         %p", process_mod_ex.end);

	//-- Allocate Memory
	mem::voidptr_t alloc_ex = mem::ex::allocate(process_ex, sizeof(int), PROTECTION);
	tprint("Allocated memory:   %p", alloc_ex);

	//-- Writing to Memory

	int write_buffer_ex = 10;
	mem::ex::write(process_ex, alloc_ex, &write_buffer_ex, sizeof(write_buffer_ex));
	tprint("Wrote '%i' to:      %p", write_buffer_ex, alloc_ex);

	//-- Reading from Memory
	int read_buffer_ex = 0;
	mem::ex::read(process_ex, alloc_ex, &read_buffer_ex, sizeof(read_buffer_ex));
	tprint("Read  '%i' from:    %p", read_buffer_ex, alloc_ex);

	//-- Pattern Scanning
	mem::data_t pattern = { 0x10, 0x20, 0x0, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0x00, 0xB0 };
	mem::string_t mask = MEM_STR("xx?xxxxxxxx?x");
	mem::voidptr_t scan = mem::ex::pattern_scan(process_ex, pattern, mask, (mem::voidptr_t)((mem::uintptr_t)pattern.data() - 0x10), (mem::voidptr_t)((mem::uintptr_t)pattern.data() + 0x10));
	tprint("Pattern Scan:       %p", scan);
	tprint(" (expected result): %p", (mem::voidptr_t)pattern.data());

	//-- Get Page Information
	mem::page_t page_ex = mem::ex::get_page(process_ex, process_mod_ex.base);
	tprint("Page Base:          %p", page_ex.base);
	tprint("Page Size:          %p", (mem::voidptr_t)page_ex.size);
	tprint("Page End:           %p", page_ex.end);
	tprint("Page Protection:    %i", (mem::int_t)page_ex.protection);
	tprint("Page Flags:         %i", (mem::int_t)page_ex.flags);

	print();
	print("====================");
	print();

	//====================

	//Internal

	print("Internal tests:");

	//-- Get Process ID
	mem::pid_t pid_in = mem::in::get_pid();
	tprint("PID:                %i", pid_in);

	//-- Get Process Information
	mem::process_t process_in = mem::in::get_process();
	tprint("Process Name:       %s", process_in.name.c_str());
	tprint("Process ID:         %i", process_in.pid);

	//-- Get Process Module
	mem::module_t process_mod_in = mem::in::get_module(PROCESS_NAME);
	tprint("Module Name:        %s", process_mod_in.name.c_str());
	tprint("Module Path:        %s", process_mod_in.path.c_str());
	tprint("Module Base:        %p", process_mod_in.base);
	tprint("Module Size:        %p", (mem::voidptr_t)process_mod_in.size);
	tprint("Module End:         %p", process_mod_in.end);

	//-- Allocate Memory

	mem::voidptr_t alloc_in = mem::in::allocate(sizeof(int), PROTECTION);
	tprint("Allocated memory:   %p", alloc_in);

	//-- Write to Memory
	int write_buffer_in = 1337;
	mem::in::write(alloc_in, &write_buffer_in, sizeof(write_buffer_in));
	tprint("Wrote '%i' to:    %p", write_buffer_in, alloc_in);

	//-- Read from Memory

	int read_buffer_in = 0;
	mem::in::read(alloc_in, &read_buffer_in, sizeof(read_buffer_in));
	tprint("Read  '%i' from:  %p", read_buffer_in, alloc_in);

	//-- Pattern Scanning

	mem::voidptr_t scan_in = mem::in::pattern_scan(pattern, mask, (mem::voidptr_t)((mem::uintptr_t)pattern.data() - 0x10), (mem::voidptr_t)((mem::uintptr_t)pattern.data() + 0x10));
	tprint("Pattern Scan:       %p", scan_in);
	tprint(" (expected result): %p", (mem::voidptr_t)pattern.data());

	//-- Get Page Information
	mem::page_t page_in = mem::in::get_page(process_mod_in.base);
	tprint("Page Base:          %p", page_in.base);
	tprint("Page Size:          %p", (mem::voidptr_t)page_in.size);
	tprint("Page End:           %p", page_in.end);
	tprint("Page Protection:    %i", (mem::int_t)page_in.protection);
	tprint("Page Flags:         %i", (mem::int_t)page_in.flags);

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