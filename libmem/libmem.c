/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * | https://github.com/rdbo/libmem   |
 *  ----------------------------------
 */

#include "libmem.h"

#ifdef MEM_COMPATIBLE

 //Data
#if   MEM_ARCH == x86_32
static const mem_payload_t g_mem_payloads[] = {
	{ (mem_data_t)"\xE9\x00\x00\x00\x00", 5 },                              //x86_JMP32
	{ (mem_data_t)"\xB8\x00\x00\x00\x00\xFF\xE0", 7 },                      //x86_JMP64
	{ (mem_data_t)"\xE8\x00\x00\x00\x00", 5 },                              //x86_CALL32
	{ (mem_data_t)"\xB8\x00\x00\x00\x00\xFF\xD0", 7 },                      //x86_CALL64
};
#elif MEM_ARCH == x86_64
static const mem_payload_t g_mem_payloads[] = {
	{ (mem_data_t)"\xE9\x00\x00\x00\x00", 5 },                              //x86_JMP32
	{ (mem_data_t)"\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xE0", 12 }, //x86_JMP64
	{ (mem_data_t)"\xE8\x00\x00\x00\x00", 5 },                              //x86_CALL32
	{ (mem_data_t)"\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xD0", 12 }, //x86_CALL64
};
#endif

//mem_in

mem_pid_t          mem_in_get_pid()
{
	/*
	 * Description:
	 *   Gets the process id of 
	 *   the caller
	 *
	 * Return Value:
	 *   Process ID of the caller
	 *   or 'MEM_BAD' on error
	 */

	mem_pid_t pid = (mem_pid_t)MEM_BAD;
#	if   MEM_OS == MEM_WIN
	pid = (mem_pid_t)GetCurrentProcessId();
#	elif MEM_OS == MEM_LINUX
	pid = (mem_pid_t)getpid();
#	endif
	return pid;
}

mem_size_t         mem_in_get_process_name(mem_tstring_t* pprocess_name)
{
	/*
	 * Description:
	 *   Gets the process name of
	 *   the caller
	 *
	 * Return Value:
	 *   Returns the count of
	 *   read characters
	 *
	 * Remarks:
	 *   The process name is saved on
	 *   'pprocess_name' and needs to
	 *   be free'd
	 */

	mem_size_t read_chars = 0;
#	if MEM_OS == MEM_WIN
	*pprocess_name = (mem_tstring_t)malloc(MEM_PATH_MAX * sizeof(mem_tchar_t));
	read_chars = (mem_size_t)GetModuleFileName(NULL, *pprocess_name, MEM_PATH_MAX);
#	elif MEM_OS == MEM_LINUX
	read_chars = mem_ex_get_process_name(mem_in_get_pid(), pprocess_name);
#	endif

	return read_chars;
}

mem_arch_t         mem_in_get_arch()
{
	/*
	 * Description:
	 *   Gets the architecture of
	 *   the caller process
	 *
	 * Return Value:
	 *   Returns the architecture
	 *   of the caller process or
	 *   'arch_unknown' if the
	 *   architecture is not
	 *   recognized
	 */

	return (mem_arch_t)MEM_ARCH;
}

mem_process_t      mem_in_get_process()
{
	/*
	 * Description:
	 *   Gets information about
	 *   the caller process
	 *
	 * Return Value:
	 *   Returns information about
	 *   the caller process or a
	 *   'mem_process_t' filled with
	 *   invalid values on error
	 */

	mem_process_t process = { 0 };
	process.pid  = mem_in_get_pid();
	process.arch = mem_in_get_arch();
	return process;
}

mem_module_t       mem_in_get_module(mem_tstring_t module_ref)
{
	/*
	 * Description:
	 *   Gets information about
	 *   the caller process
	 *
	 * Return Value:
	 *   Returns information about
	 *   the caller process or a
	 *   'mem_module_t' filled with
	 *   invalid values on error
	 */

	mem_module_t mod = { 0 };
#	if MEM_OS == MEM_WIN
	MODULEINFO mod_info = { 0 };
	HMODULE hModule = INVALID_HANDLE_VALUE;
	hModule = GetModuleHandle(module_ref);
	if (!hModule || hModule == INVALID_HANDLE_VALUE) return mod;
	GetModuleInformation(GetCurrentProcess(), hModule, &mod_info, sizeof(mod_info));
	CloseHandle(hModule);

	mod.base = (mem_voidptr_t)mod_info.lpBaseOfDll;
	mod.size = (mem_size_t)mod_info.SizeOfImage;
	mod.end  = (mem_voidptr_t)((mem_uintptr_t)mod.base + mod.size);

#	elif MEM_OS == MEM_LINUX
	mod = mem_ex_get_module(mem_in_get_process(), module_ref);
#	endif
	return mod;
}

mem_size_t         mem_in_get_module_path(mem_module_t mod, mem_tstring_t* pmodule_path)
{
	/*
	 * Description:
	 *   Gets the module path of 'mod'
	 *
	 * Return Value:
	 *   Returns the count of
	 *   read characters
	 *
	 * Remarks:
	 *   The module path is saved on
	 *   'pmodule_path' and needs to
	 *   be free'd
	 */

	mem_size_t read_chars = 0;

#	if   MEM_OS == MEM_WIN
	HMODULE hModule = INVALID_HANDLE_VALUE;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)mod.base, &hModule);
	if (hModule && hModule != INVALID_HANDLE_VALUE)
	{
		mem_size_t path_size = MEM_PATH_MAX * sizeof(mem_tchar_t);
		*pmodule_path = (mem_tstring_t)malloc(path_size);
		if (!*pmodule_path) return read_chars;
		mem_in_set(*pmodule_path, 0x0, path_size);
		read_chars = (mem_size_t)GetModuleFileName(hModule, *pmodule_path, MEM_PATH_MAX);
		CloseHandle(hModule);
	}
#	elif MEM_OS == MEM_LINUX
	read_chars = mem_ex_get_module_path(mem_in_get_process(), mod, pmodule_path);
#	endif

	return read_chars;
}

mem_size_t         mem_in_get_module_list(mem_module_t** pmodule_list)
{
	/*
	 * Description:
	 *   Gets the module list of
	 *   the caller process
	 *
	 * Return Value:
	 *   Returns the length of
	 *   the module list buffer
	 *
	 * Remarks:
	 *   The module list is saved on
	 *   'pmodule_list' and needs to
	 *   be free'd
	 */

	return mem_ex_get_module_list(mem_in_get_process(), pmodule_list);
}

mem_page_t         mem_in_get_page(mem_voidptr_t src)
{
	/*
	 * Description:
	 *   Gets information about the
	 *   page 'src' is in
	 *
	 * Return Value:
	 *   Returns information about the
	 *   page 'src' is in or a 'page_t'
	 *   filled with invalid values
	 */

	mem_page_t page = { 0 };
#	if   MEM_OS == MEM_WIN
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	VirtualQuery((LPCVOID)src, &mbi, sizeof(mbi));
	page.base = mbi.BaseAddress;
	page.size = mbi.RegionSize;
	page.end = (mem_voidptr_t)((mem_uintptr_t)page.base + page.size);
	page.protection = mbi.Protect;
	page.flags = mbi.Type;
#	elif MEM_OS == MEM_LINUX
	page = mem_ex_get_page(mem_in_get_process(), src);
#	endif
	return page;
}

mem_bool_t         mem_in_read(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size)
{
	/*
	 * Description:
	 *   Reads 'size' bytes from
	 *   'src' and saves them into
	 *   'dst'.
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 *
	 * Remarks:
	 *   This function does not check
	 *   or change the protection of
	 *   'src' and 'dst' addresses
	 */

	return memcpy(dst, src, size) == (void*)dst ? MEM_TRUE : MEM_FALSE;
}

mem_bool_t         mem_in_write(mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size)
{
	/*
	 * Description:
	 *   Writes 'size' bytes from
	 *   'src' into 'dst'.
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 *
	 * Remarks:
	 *   This function does not check
	 *   or change the protection of
	 *   'src' and 'dst' addresses
	 */

	return memcpy(src, dst, size) == (void*)src ? MEM_TRUE : MEM_FALSE;
}

mem_bool_t         mem_in_set(mem_voidptr_t src, mem_byte_t byte, mem_size_t size)
{
	/*
	 * Description:
	 *   Writes 'size' bytes of 
	 *   value 'byte' into 'dst'.
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 *
	 * Remarks:
	 *   This function does not check
	 *   or change the protection of
	 *   the 'src' address
	 */

	return memset(src, byte, size) == (void*)src ? MEM_TRUE : MEM_FALSE;
}

mem_voidptr_t      mem_in_syscall(mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5)
{
	/*
	 * Description:
	 *   Runs the syscall 'syscall_n' with
	 *   up to 6 arguments (arg0 ... arg5)
	 *
	 * Return Value:
	 *   Returns the value returned by
	 *   the syscall
	 */

	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD;
#	if   MEM_OS == MEM_WIN
#	elif MEM_OS == MEM_LINUX
	ret = (mem_voidptr_t)syscall(syscall_n, arg0, arg1, arg2, arg3, arg4, arg5);
#	endif
	return ret;
}

mem_bool_t         mem_in_protect(mem_voidptr_t src, mem_size_t size, mem_prot_t protection, mem_prot_t* pold_protection)
{
	/*
	 * Description:
	 *   Changes the protection flags
	 *   from page of 'src' to 'size' bytes
	 *   after to 'protection'
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
	mem_prot_t old_protection = 0;
#	if   MEM_OS == MEM_WIN
	ret = VirtualProtect(src, size, protection, &old_protection) != 0 ? MEM_TRUE : MEM_FALSE;
#	elif MEM_OS == MEM_LINUX
	long page_size = sysconf(_SC_PAGE_SIZE);
	void* src_page = (void*)((uintptr_t)src & -page_size);
	mem_page_t page = mem_in_get_page((mem_voidptr_t)src_page);
	old_protection = page.protection;
	ret = mprotect(src_page, size, protection) == 0 ? MEM_TRUE : MEM_FALSE;
#	endif

	if (pold_protection) *pold_protection = old_protection;

	return ret;
}

mem_voidptr_t      mem_in_allocate(mem_size_t size, mem_prot_t protection)
{
	/*
	 * Description:
	 *   Allocates 'size' bytes of memory
	 *   with the protection flags 'protection'
	 *
	 * Return Value:
	 *   Returns the address of the allocated
	 *   memory or 'MEM_BAD' on error
	 */

	mem_voidptr_t alloc = (mem_voidptr_t)MEM_BAD;

#	if   MEM_OS == MEM_WIN
	alloc = (mem_voidptr_t)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protection);
	if (!alloc) alloc = (mem_voidptr_t)MEM_BAD;
#	elif MEM_OS == MEM_LINUX
	alloc = (mem_voidptr_t)mmap(NULL, size, protection, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (alloc == (mem_voidptr_t)MAP_FAILED) alloc = (mem_voidptr_t)MEM_BAD;
#	endif

	return alloc;
}

mem_bool_t         mem_in_deallocate(mem_voidptr_t src, mem_size_t size)
{
	/*
	 * Description:
	 *   Deallocates 'size' bytes of 'src'
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
#	if   MEM_OS == MEM_WIN
	ret = VirtualFree(src, 0, MEM_RELEASE) != 0 ? MEM_TRUE : MEM_FALSE;
#	elif MEM_OS == MEM_LINUX
	ret = munmap(src, size) == 0 ? MEM_TRUE : MEM_FALSE;
#	endif

	return ret;
}

mem_voidptr_t      mem_in_scan(mem_data_t data, mem_size_t size, mem_voidptr_t start, mem_voidptr_t stop)
{
	/*
	 * Description:
	 *   Searches for 'size' bytes of 'data'
	 *   from 'start' to 'stop'
	 *
	 * Return Value:
	 *   Returns the first occurrence of 'data'
	 *   between 'start' and 'stop' or 'MEM_BAD'
	 *   if no occurrence was found
	 */

	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD;

	for (mem_data_t i = (mem_data_t)start; (mem_uintptr_t)&i[size] <= (mem_uintptr_t)stop; i = &i[1])
	{
		mem_int_t found = MEM_TRUE;
		for (size_t j = 0; j < size; j++)
		{
			found &= i[j] == data[j];

			if (!found) break;
		}

		if (found)
		{
			ret = (mem_voidptr_t)i;
			break;
		}
	}

	return ret;
}

mem_voidptr_t      mem_in_pattern_scan(mem_data_t pattern, mem_tstring_t mask, mem_voidptr_t start, mem_voidptr_t stop)
{
	/*
	 * Description:
	 *   Searches for 'size' bytes of 'data'
	 *   from 'start' to 'stop' and checks
	 *   a byte mask
	 *
	 * Return Value:
	 *   Returns the first occurrence of 'data'
	 *   between 'start' and 'stop' or 'MEM_BAD'
	 *   if no occurrence was found
	 */

	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD;
	size_t size = MEM_STR_LEN(mask);

	for (mem_data_t i = (mem_data_t)start; (mem_uintptr_t)&i[size] <= (mem_uintptr_t)stop; i = &i[1])
	{
		mem_int_t found = MEM_TRUE;
		for (size_t j = 0; j < size; j++)
		{
			found &= (mask[j] == MEM_STR('x') || mask[j] == MEM_STR('X') || i[j] == pattern[j]);

			if (!found) break;
		}

		if (found)
		{
			ret = (mem_voidptr_t)i;
			break;
		}
	}

	return ret;
}

mem_size_t         mem_in_detour_size(mem_detour_t method)
{
	/*
	 * Description:
	 *   Gets the size of the detour method 'method'
	 *
	 * Return Value:
	 *   Returns the size of the detour method 'method'
	 *   or 'MEM_BAD' on error
	 */

	mem_size_t size = (mem_size_t)MEM_BAD;

	if (method < detour_unknown)
		size = g_mem_payloads[method].size;

	return size;
}

mem_bool_t         mem_in_detour(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_data_t* stolen_bytes)
{
	/*
	 * Description:
	 *   Detours 'src' to 'dst' using the
	 *   detour method 'method' and saves
	 *   'size' bytes of 'src' into 'stolen_bytes'
	 *   if 'stolen_bytes' is not null
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
	mem_size_t detour_size = mem_in_detour_size(method);
	mem_prot_t protection = 0;

#	if   MEM_OS == MEM_WIN
	protection = PAGE_EXECUTE_READWRITE;
#	elif MEM_OS == MEM_LINUX
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif

	if (detour_size == (mem_size_t)MEM_BAD || size < detour_size || mem_in_protect(src, size, protection, NULL) == MEM_FALSE) return ret;

	if (stolen_bytes)
	{
		*stolen_bytes = malloc(size);
		if (*stolen_bytes)
		{
			for (mem_size_t i = 0; i < size; ++i)
				*stolen_bytes[i] = ((mem_data_t)src)[i];
		}
	}

	mem_data_t detour_buffer = (mem_data_t)malloc(detour_size);
	if (!detour_buffer) return ret;
	mem_in_read((mem_voidptr_t)g_mem_payloads[method].payload, detour_buffer, detour_size);

#	if   MEM_ARCH == x86_32
	switch (method)
	{
	case x86_JMP32:
		*(mem_voidptr_t*)(&detour_buffer[1]) = (mem_voidptr_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		break;
	case x86_JMP64:
		*(mem_voidptr_t*)(&detour_buffer[1]) = dst;
		break;
	case x86_CALL32:
		*(mem_voidptr_t*)(&detour_buffer[1]) = (mem_voidptr_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		break;
	case x86_CALL64:
		*(mem_voidptr_t*)(&detour_buffer[1]) = dst;
		break;
	default:
		break;
	}
#	elif MEM_ARCH == x86_64
	switch (method)
	{
	case x86_JMP32:
		*(mem_voidptr_t*)(&detour_buffer[1]) = (mem_voidptr_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		break;
	case x86_JMP64:
		*(mem_voidptr_t*)(&detour_buffer[2]) = dst;
		break;
	case x86_CALL32:
		*(mem_voidptr_t*)(&detour_buffer[1]) = (mem_voidptr_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		break;
	case x86_CALL64:
		*(mem_voidptr_t*)(&detour_buffer[2]) = dst;
		break;
	default:
		break;
	}
#	endif

	mem_in_write(src, detour_buffer, detour_size);
	free(detour_buffer);

	return ret;
}

mem_voidptr_t      mem_in_detour_trampoline(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_detour_t method, mem_data_t* stolen_bytes)
{
	/*
	 * Description:
	 *   Detours 'src' to 'dst' using the
	 *   detour method 'method', saves
	 *   'size' bytes of 'src' into 'stolen_bytes'
	 *   if 'stolen_bytes' is not null and makes
	 *   an executable gateway to restore the
	 *   original execution
	 *
	 * Return Value:
	 *   Returns the address of the executable
	 *   gateway or 'MEM_BAD' on error
	 * Remarks:
	 *   The gateway returned has to be
	 *   free'd
	 */

	mem_voidptr_t gateway = (mem_voidptr_t)MEM_BAD;

	mem_size_t detour_size = mem_in_detour_size(method);
	mem_prot_t protection = 0;
#	if   MEM_OS == MEM_WIN
	protection = PAGE_EXECUTE_READWRITE;
#	elif MEM_OS == MEM_LINUX
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif

	if (detour_size == (mem_size_t)MEM_BAD || size < detour_size || mem_in_protect(src, size, protection, NULL) == MEM_FALSE) return gateway;

	size_t gateway_size = size + detour_size;
	gateway = (mem_voidptr_t)malloc(gateway_size);
	if (!gateway || mem_in_protect(gateway, gateway_size, protection, NULL) == MEM_FALSE) return (mem_voidptr_t)MEM_BAD;

	mem_data_t p_gateway = (mem_data_t)gateway;
	mem_data_t p_src = (mem_data_t)src;
	mem_in_write((mem_voidptr_t)p_gateway, src, size);
	mem_in_detour((mem_voidptr_t)& p_gateway[size], &p_src[size], detour_size, method, NULL);
	if (mem_in_detour(src, dst, size, method, stolen_bytes) == MEM_FALSE)
	{
		free(gateway);
		gateway = (mem_voidptr_t)MEM_BAD;
	}

	return gateway;
}

mem_bool_t         mem_in_detour_restore(mem_voidptr_t src, mem_data_t stolen_bytes, mem_size_t size)
{
	/*
	 * Description:
	 *   Writes 'size' bytes from
	 *   'stolen_bytes' into 'src'.
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_prot_t protection = 0;
#	if   MEM_OS == MEM_WIN
	protection = PAGE_EXECUTE_READWRITE;
#	elif MEM_OS == MEM_LINUX
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif

	mem_bool_t ret = MEM_TRUE;

	if (
		mem_in_protect(src, size, protection, NULL)          == MEM_FALSE ||
		mem_in_write(src, (mem_voidptr_t)stolen_bytes, size) == MEM_FALSE
	) ret = MEM_FALSE;

	return ret;
}

mem_module_t       mem_in_load_module(mem_tstring_t path)
{
	/*
	 * Description:
	 *   Loads the module from
	 *   'path' into the caller
	 *   process
	 *
	 * Return Value:
	 *   Returns information about
	 *   the loaded module or a
	 *   'mem_module_t' filled with
	 *   invalid values on error
	 */

	mem_module_t mod = { 0 };
#	if   MEM_OS == MEM_WIN
	HMODULE hModule = LoadLibrary(path);
	if (hModule && hModule != INVALID_HANDLE_VALUE)
	{
		mod = mem_in_get_module(path);
		CloseHandle(hModule);
	}

#	elif MEM_OS == MEM_LINUX
	if (dlopen(path, RTLD_LAZY))
		mod = mem_in_get_module(path);
#	endif

	return mod;
}

mem_bool_t         mem_in_unload_module(mem_module_t mod)
{
	/*
	 * Description:
	 *   Unloads the module 'mod' 
	 *   from the caller process
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
#	if   MEM_OS == MEM_WIN
	HMODULE hModule = INVALID_HANDLE_VALUE;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)mod.base, &hModule);
	if (hModule && hModule != INVALID_HANDLE_VALUE)
	{
		FreeLibrary(hModule);
		ret = MEM_TRUE;
	}
#	elif MEM_OS == MEM_LINUX
	mem_tstring_t mod_path = (mem_tstring_t)NULL;
	if (mem_in_get_module_path(mod, &mod_path) && dlclose(dlopen(mod_path, RTLD_LAZY)))
		ret = MEM_TRUE;
	ret = dlclose(handle) == 0 ? MEM_TRUE : MEM_FALSE;
#	endif

	return ret;
}

mem_voidptr_t      mem_in_get_symbol(mem_module_t mod, mem_cstring_t symbol)
{
	/*
	 * Description:
	 *  Gets the address of the symbol 'symbol'
	 *  of the module 'mod'
	 *
	 * Return Value:
	 *   Returns the address of the symbol
	 *   or 'MEM_BAD' on error
	 */

	mem_voidptr_t addr = (mem_voidptr_t)MEM_BAD;
#	if   MEM_OS == MEM_WIN
	HMODULE hModule = INVALID_HANDLE_VALUE;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)mod.base, &hModule);
	if (hModule && hModule != INVALID_HANDLE_VALUE)
	{
		addr = (mem_voidptr_t)GetProcAddress(hModule, symbol);
		if (!addr) addr = (mem_voidptr_t)MEM_BAD;
		CloseHandle(hModule);
	}
#	elif MEM_OS == MEM_LINUX
	mem_tstring_t mod_path = (mem_tstring_t)NULL;
	if (mem_in_get_module_path(mod, &mod_path))
	{
		void* handle = dlopen(mod_path, RTLD_LAZY);
		addr = dlsym(handle, symbol);
		if (!addr) addr = (mem_voidptr_t)MEM_BAD;
	}
#	endif

	return addr;
}

//mem_ex

mem_pid_t          mem_ex_get_pid(mem_tstring_t process_ref);
mem_size_t         mem_ex_get_process_name(mem_pid_t pid, mem_tstring_t* pprocess_name);
mem_process_t      mem_ex_get_process(mem_pid_t pid);
mem_size_t         mem_ex_get_process_list(mem_process_t** pprocess_list);
mem_module_t       mem_ex_get_module(mem_process_t process, mem_tstring_t module_ref);
mem_size_t         mem_ex_get_module_list(mem_process_t process, mem_module_t** pmodule_list);
mem_page_t         mem_ex_get_page(mem_process_t process, mem_voidptr_t src);
mem_bool_t         mem_ex_is_process_running(mem_process_t process);
mem_bool_t         mem_ex_read(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size);
mem_bool_t         mem_ex_write(mem_process_t process, mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size);
mem_bool_t         mem_ex_set(mem_process_t process, mem_voidptr_t dst, mem_byte_t byte, mem_size_t size);
mem_voidptr_t      mem_ex_syscall(mem_process_t process, mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5);
mem_bool_t         mem_ex_protect(mem_process_t process, mem_voidptr_t src, mem_size_t size, mem_prot_t protection, mem_prot_t* old_protection);
mem_voidptr_t      mem_ex_allocate(mem_process_t process, mem_size_t size, mem_prot_t protection);
mem_bool_t         mem_ex_deallocate(mem_process_t process, mem_voidptr_t src, mem_size_t size);
mem_voidptr_t      mem_ex_scan(mem_process_t process, mem_data_t data, mem_size_t size, mem_voidptr_t start, mem_voidptr_t stop);
mem_voidptr_t      mem_ex_pattern_scan(mem_process_t process, mem_data_t pattern, mem_tstring_t mask, mem_voidptr_t start, mem_voidptr_t stop);

#endif //MEM_COMPATIBLE
