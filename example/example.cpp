#include "../libmem/libmem.hpp"
#ifdef MEM_COMPATIBLE
#if   MEM_CHARSET == MEM_UCS
#define print(...) wprintf(__VA_ARGS__)
#elif MEM_CHARSET == MEM_MBCS
#define print(...) printf(__VA_ARGS__)
#endif

#if   MEM_OS == MEM_WIN
#define NAKEDFN __declspec(naked) void
#elif MEM_OS == MEM_LINUX
#define NAKEDFN void __attribute__((naked))
#endif

#if   MEM_ARCH == _MEM_ARCH_x86_32
#define EXAMPLE_HOOK 1
#elif MEM_ARCH == _MEM_ARCH_x86_64
#define EXAMPLE_HOOK 0
#endif

#define tprint(...)  print(MEM_STR("    ") __VA_ARGS__)
#define separator()  print(MEM_STR("--------------------\n"))
#define tseparator() tprint(MEM_STR("--------------------\n"))
#define arch_to_str(arch) (arch == MEM_ARCH_x86_32 ? "x86_32" : arch == MEM_ARCH_x86_64 ? "x86_64" : "Unknown")
#define print_logo() print(MEM_STR("\n\
/*\n\
 *  ----------------------------------\n\
 * |        libmem++ - by rdbo        |\n\
 * |  https://github.com/rdbo/libmem  |\n\
 *  ----------------------------------\n\
 */\n\
\n"))

#if   EXAMPLE_HOOK

mem_voidptr_t HookReturn = NULL;

void success_function()
{
	tprint(MEM_STR("Hooked Succeeded!\n"));
}

void failure_function()
{
	tprint(MEM_STR("Hook Failed!\n"));
}

NAKEDFN target_function(void* fn)
{
#	ifdef _MSC_VER
	__asm
	{
		//Bytes for the hook
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop

		push ebp
		mov ebp, esp
		push eax
		//Call function passed in 'fn'
		mov eax, [ebp + 8]
		call eax
		pop eax

		mov esp, ebp
		pop ebp
		ret
	}
#	else
#	endif
}

NAKEDFN hook_function()
{
#	if   MEM_OS == MEM_WIN
	__asm
	{
		push eax
		mov eax, success_function
		mov[ebp + 8], eax
		pop eax
		jmp HookReturn
	}
#	elif MEM_OS == MEM_LINUX
#	endif
}

#endif //MEM_ARCH

int main()
{
	//Data
	mem_pid_t     pid = 0;
	mem_process_t process = { 0 };
	mem_string_t  process_name = MEM_STR("");
	mem_string_t  process_path = MEM_STR("");

	mem_module_t  mod = { 0 };
	mem_string_t  module_name = MEM_STR("");
	mem_string_t  module_path = MEM_STR("");

	mem_page_t    page = { 0 };
	mem_byte_t    pattern[] = { 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 };
	mem_string_t  mask = MEM_STR("xxxxxxxxx");
	mem_voidptr_t scan = (mem_voidptr_t)MEM_BAD;
	mem_voidptr_t pattern_scan = (mem_voidptr_t)MEM_BAD;

	mem_voidptr_t alloc = (mem_voidptr_t)MEM_BAD;
	mem_prot_t    protection = 0;
	int read_buf = 0;
	int write_buf = 1337;
#	if   MEM_OS == MEM_WIN
	protection = PAGE_EXECUTE_READWRITE;
#	elif MEM_OS == MEM_LINUX
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif

	//Examples
	print_logo();
	print(MEM_STR("Press [ENTER] to start..."));
	getchar();

	print(MEM_STR("Internal: \n"));
	process_name = mem::in::get_process_name();
	process_path = mem::in::get_process_path();
	pid = mem::in::get_pid();
	process = mem::in::get_process();

	tprint(MEM_STR("Process Name:    %s\n"), process_name.c_str());
	tprint(MEM_STR("Process Path:    %s\n"), process_path.c_str());
	tprint(MEM_STR("Process ID:      %p\n"), (void*)pid);
	tprint(MEM_STR("Process Arch:    %s\n"), arch_to_str(process.arch));
	tseparator();

	mod = mem::in::get_module(process_path);
	module_name = mem::in::get_module_name(mod);
	module_path = mem::in::get_module_path(mod);
	tprint(MEM_STR("Module Name:     %s\n"), module_name.c_str());
	tprint(MEM_STR("Module Path:     %s\n"), module_path.c_str());
	tprint(MEM_STR("Module Base:     %p\n"), mod.base);
	tprint(MEM_STR("Module Size:     %p\n"), (void*)mod.size);
	tprint(MEM_STR("Module End:      %p\n"), mod.end);
	tseparator();

	page = mem::in::get_page(mod.base);
	tprint(MEM_STR("Page Base:       %p\n"), page.base);
	tprint(MEM_STR("Page Size:       %p\n"), (void*)page.size);
	tprint(MEM_STR("Page End:        %p\n"), page.end);
	tprint(MEM_STR("Page Protection: %p\n"), (void*)page.protection);
	tprint(MEM_STR("Page Flags:      %p\n"), (void*)page.flags);
	tseparator();

	mem_voidptr_t scan_start = (mem_voidptr_t)&pattern[-10];
	mem_voidptr_t scan_stop = (mem_voidptr_t)&pattern[10];
	scan = mem::in::scan(pattern, sizeof(pattern), scan_start, scan_stop);
	pattern_scan = mem::in::pattern_scan(pattern, mask, scan_start, scan_stop);
	tprint(MEM_STR("Scan:            %p\n"), scan);
	tprint(MEM_STR("Pattern Scan:    %p\n"), pattern_scan);
	tprint(MEM_STR("Expected Result: %p\n"), (void*)pattern);
	tseparator();

	alloc = mem::in::allocate(sizeof(write_buf), protection);
	mem::in::write(alloc, &write_buf, sizeof(write_buf));
	mem::in::read(alloc, &read_buf, sizeof(read_buf));
	mem::in::deallocate(alloc, sizeof(write_buf));
	tprint(MEM_STR("Allocation:      %p\n"), alloc);
	tprint(MEM_STR("Written:         %i\n"), write_buf);
	tprint(MEM_STR("Read:            %i\n"), read_buf);
	tseparator();

#	if   EXAMPLE_HOOK
	tprint(MEM_STR("Target Function: %p\n"), (void*)target_function);
	tprint(MEM_STR("Hook   Function: %p\n"), (void*)hook_function);
	mem_byte_t* p_target_function = (mem_byte_t*)target_function;
	if (p_target_function[0] == 0xE9) p_target_function = &p_target_function[(*(mem_intptr_t*)(&p_target_function[1])) + 5];
	HookReturn = mem::in::detour_trampoline((mem_voidptr_t)p_target_function, (mem_voidptr_t)hook_function, mem::in::detour_size(MEM_ASM_x86_JMP32), MEM_ASM_x86_JMP32, NULL);
	target_function((void*)failure_function);
	tseparator();
#	endif

	print(MEM_STR("Press [ENTER] to exit..."));
	getchar();
	return 0;
}
#endif