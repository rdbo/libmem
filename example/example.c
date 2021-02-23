#include "../libmem/libmem.h"
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
 * |         libmem - by rdbo         |\n\
 * |      Memory Hacking Library      |\n\
 *  ----------------------------------\n\
 */\n\
\n"))

int main()
{
	/* Data */
	mem_pid_t     pid = 0;
	mem_process_t process = { 0 };
	mem_tstring_t process_name = (mem_tstring_t)NULL;
	mem_tstring_t process_path = (mem_tstring_t)NULL;

	mem_module_t  mod = { 0 };
	mem_tstring_t module_name = (mem_tstring_t)NULL;
	mem_tstring_t module_path = (mem_tstring_t)NULL;

	mem_page_t    page = { 0 };
	mem_byte_t    pattern[] = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };
	mem_string_t  mask = MEM_STR("xxxxxxxxx");
	mem_string_t  signature = MEM_STR("10 20 ?? 40 50 ?? 70 80 ?? A0");
	mem_voidptr_t scan = (mem_voidptr_t)MEM_BAD;
	mem_voidptr_t pattern_scan = (mem_voidptr_t)MEM_BAD;
	mem_voidptr_t signature_scan = (mem_voidptr_t)MEM_BAD;

	mem_voidptr_t alloc = (mem_voidptr_t)MEM_BAD;
	mem_prot_t    protection = 0;
	int read_buf  = 0;
	int write_buf = 1337;
#	if   MEM_OS == MEM_WIN
	protection = PAGE_EXECUTE_READWRITE;
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif

	/* Examples */
	print_logo();
	print(MEM_STR("Press [ENTER] to start..."));
	getchar();

	print(MEM_STR("Internal: \n"));
	mem_in_get_process_name(&process_name);
	mem_in_get_process_path(&process_path);
	pid = mem_in_get_pid();
	process = mem_in_get_process();

	tprint(MEM_STR("Process Name:    %s\n"), process_name);
	tprint(MEM_STR("Process Path:    %s\n"), process_path);
	tprint(MEM_STR("Process ID:      %p\n"), (void *)(uintptr_t)pid);
	tprint(MEM_STR("Process Arch:    %s\n"), arch_to_str(process.arch));
	tseparator();

	mod = mem_in_get_module(process_path);
	mem_in_get_module_name(mod, &module_name);
	mem_in_get_module_path(mod, &module_path);
	tprint(MEM_STR("Module Name:     %s\n"), module_name);
	tprint(MEM_STR("Module Path:     %s\n"), module_path);
	tprint(MEM_STR("Module Base:     %p\n"), mod.base);
	tprint(MEM_STR("Module Size:     %p\n"), (void *)(uintptr_t)mod.size);
	tprint(MEM_STR("Module End:      %p\n"), mod.end);
	tseparator();

	page = mem_in_get_page(mod.base);
	tprint(MEM_STR("Page Base:       %p\n"), page.base);
	tprint(MEM_STR("Page Size:       %p\n"), (void *)(uintptr_t)page.size);
	tprint(MEM_STR("Page End:        %p\n"), page.end);
	tprint(MEM_STR("Page Protection: %p\n"), (void *)(uintptr_t)page.protection);
	tprint(MEM_STR("Page Flags:      %p\n"), (void *)(uintptr_t)page.flags);
	tseparator();

	mem_voidptr_t scan_start = (mem_voidptr_t)&pattern[-10];
	mem_voidptr_t scan_stop = (mem_voidptr_t)&pattern[10];
	scan = mem_in_scan(pattern, sizeof(pattern), scan_start, scan_stop);
	pattern_scan = mem_in_pattern_scan(pattern, mask, scan_start, scan_stop);
	signature_scan = mem_in_signature_scan(signature, scan_start, scan_stop);
	tprint(MEM_STR("Scan:            %p\n"), scan);
	tprint(MEM_STR("Pattern Scan:    %p\n"), pattern_scan);
	tprint(MEM_STR("Signature Scan:  %p\n"), signature_scan);
	tprint(MEM_STR("Expected Result: %p\n"), (void *)(uintptr_t)pattern);
	tseparator();

	alloc = mem_in_allocate(sizeof(write_buf), protection);
	mem_in_write(alloc, &write_buf, sizeof(write_buf));
	mem_in_read(alloc, &read_buf, sizeof(read_buf));
	mem_in_deallocate(alloc, sizeof(write_buf));
	tprint(MEM_STR("Allocation:      %p\n"), alloc);
	tprint(MEM_STR("Written:         %i\n"), write_buf);
	tprint(MEM_STR("Read:            %i\n"), read_buf);
	tseparator();

	/* Free memory */
	free(module_path);
	free(module_name);
	free(process_path);
	free(process_name);

	print(MEM_STR("Press [ENTER] to exit..."));
	getchar();
	return 0;
}
#endif