#include "../libmem/libmem.hpp"
#ifdef MEM_COMPATIBLE
#if   MEM_CHARSET == MEM_UCS
#define print(...) wprintf(__VA_ARGS__)
#elif MEM_CHARSET == MEM_MBCS
#define print(...) printf(__VA_ARGS__)
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

int main()
{
	/* Data */
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

	/* Examples */
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
	tprint(MEM_STR("Process ID:      %p\n"), (void *)(uintptr_t)pid);
	tprint(MEM_STR("Process Arch:    %s\n"), arch_to_str(process.arch));
	tseparator();

	mod = mem::in::get_module(process_path);
	module_name = mem::in::get_module_name(mod);
	module_path = mem::in::get_module_path(mod);
	tprint(MEM_STR("Module Name:     %s\n"), module_name.c_str());
	tprint(MEM_STR("Module Path:     %s\n"), module_path.c_str());
	tprint(MEM_STR("Module Base:     %p\n"), mod.base);
	tprint(MEM_STR("Module Size:     %p\n"), (void *)(uintptr_t)mod.size);
	tprint(MEM_STR("Module End:      %p\n"), mod.end);
	tseparator();

	page = mem::in::get_page(mod.base);
	tprint(MEM_STR("Page Base:       %p\n"), page.base);
	tprint(MEM_STR("Page Size:       %p\n"), (void *)(uintptr_t)page.size);
	tprint(MEM_STR("Page End:        %p\n"), page.end);
	tprint(MEM_STR("Page Protection: %p\n"), (void*)(uintptr_t)page.protection);
	tprint(MEM_STR("Page Flags:      %p\n"), (void*)(uintptr_t)page.flags);
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

	print(MEM_STR("Press [ENTER] to exit..."));
	getchar();
	return 0;
}
#endif