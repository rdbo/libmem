/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

#include "libmem.h"

#ifdef MEM_COMPATIBLE

/* Data */
#if   MEM_ARCH == _MEM_ARCH_x86_32
static const mem_payload_t MEM_PAYLOADS[MEM_ASM_INVALID + 1] = 
{
	{ (mem_data_t)"\xE9\x00\x00\x00\x00",             5 },                  /* MEM_ASM_x86_JMP32 */
	{ (mem_data_t)"\xB8\x00\x00\x00\x00\xFF\xE0",     7 },                  /* MEM_ASM_x86_JMP64 */
	{ (mem_data_t)"\xE8\x00\x00\x00\x00",             5 },                  /* MEM_ASM_x86_CALL32 */
	{ (mem_data_t)"\xB8\x00\x00\x00\x00\xFF\xD0",     7 },                  /* MEM_ASM_x86_CALL64 */
	{ (mem_data_t)NULL,                               0 },                  /* MEM_ASM_DETOUR_INVALID */
	{ (mem_data_t)"\xCD\x80\x90\x90\x90\x90\x90\x90", 8 },                  /* MEM_ASM_x86_SYSCALL32 */
	{ (mem_data_t)"\x0F\x05\x90\x90\x90\x90\x90\x90", 8 },                  /* MEM_ASM_x86_SYSCALL64 */
	{ (mem_data_t)"\x53\xFF\xD0\xCC",                 4 },                  /* MEM_ASM_x86_LIBCALL32_1 */
	{ (mem_data_t)"\x51\x53\xFF\xD0\xCC",             5 },                  /* MEM_ASM_x86_LIBCALL32_2 */
	{ (mem_data_t)"\xFF\xD0\xCC",                     3 },                  /* MEM_ASM_x86_LIBCALL64 */
	{ (mem_data_t)NULL,                               0 },                  /* MEM_ASM_INVALID */
};
#elif MEM_ARCH == _MEM_ARCH_x86_64
static const mem_payload_t MEM_PAYLOADS[MEM_ASM_INVALID + 1] = 
{
	{ (mem_data_t)"\xE9\x00\x00\x00\x00",                              5 }, /* MEM_ASM_x86_JMP32 */
	{ (mem_data_t)"\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xE0", 12 }, /* MEM_ASM_x86_JMP64 */
	{ (mem_data_t)"\xE8\x00\x00\x00\x00",                              5 }, /* MEM_ASM_x86_CALL32 */
	{ (mem_data_t)"\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xD0", 12 }, /* MEM_ASM_x86_CALL64 */
	{ (mem_data_t)NULL,                                                0 }, /* MEM_ASM_DETOUR_INVALID */
	{ (mem_data_t)"\xCD\x80\x90\x90\x90\x90\x90\x90",                  8 }, /* MEM_ASM_x86_SYSCALL32 */
	{ (mem_data_t)"\x0F\x05\x90\x90\x90\x90\x90\x90",                  8 }, /* MEM_ASM_x86_SYSCALL64 */
	{ (mem_data_t)"\x53\xFF\xD0\xCC",                                  4 }, /* MEM_ASM_x86_LIBCALL32_1 */
	{ (mem_data_t)"\x51\x53\xFF\xD0\xCC",                              5 }, /* MEM_ASM_x86_LIBCALL32_2 */
	{ (mem_data_t)"\xFF\xD0\xCC",                                      3 }, /* MEM_ASM_x86_LIBCALL64 */
	{ (mem_data_t)NULL,                                                0 }, /* MEM_ASM_INVALID */
};
#endif

/* mem_in */

LIBMEM_EXTERN mem_pid_t          mem_in_get_pid(mem_void_t)
{
	/*
	 * Description:
	 *   Gets the process id of 
	 *   the caller process
	 *
	 * Return Value:
	 *   Process ID of the caller process
	 *   or 'MEM_BAD' on error
	 */

	mem_pid_t pid = (mem_pid_t)MEM_BAD;
#	if   MEM_OS == MEM_WIN
	pid = (mem_pid_t)GetCurrentProcessId();
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	pid = (mem_pid_t)getpid();
#	endif
	return pid;
}

LIBMEM_EXTERN mem_size_t         mem_in_get_process_name(mem_tstring_t *pprocess_name)
{
	/*
	 * Description:
	 *   Gets the process name of
	 *   the caller process
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
	mem_tstring_t process_path = (mem_tstring_t)NULL;
	if (mem_in_get_process_path(&process_path))
	{
		mem_tchar_t *p_pos = process_path;
		mem_tchar_t *temp = (mem_tchar_t *)NULL;

		for (temp = &p_pos[-1]; (temp = MEM_STR_CHR(&temp[1], MEM_STR('\\'))) != NULL; p_pos = &temp[1]);

		read_chars = MEM_STR_LEN(process_path) - (((uintptr_t)p_pos - (uintptr_t)process_path) / sizeof(mem_tchar_t));
		mem_size_t process_name_size = (read_chars + 1) * sizeof(mem_tchar_t);
		*pprocess_name = (mem_tstring_t)malloc(process_name_size);
		if (*pprocess_name)
		{
			memset(*pprocess_name, 0x0, process_name_size);
			memcpy(*pprocess_name, p_pos, read_chars * sizeof(mem_tchar_t));
		}

		else
		{
			read_chars = 0;
		}

		free(process_path);
	}
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	read_chars = mem_ex_get_process_name(mem_in_get_pid(), pprocess_name);
#	endif

	return read_chars;
}

LIBMEM_EXTERN mem_size_t         mem_in_get_process_path(mem_tstring_t *pprocess_path)
{
	/*
	 * Description:
	 *   Gets the path of
	 *   the caller process
	 *
	 * Return Value:
	 *   Returns the count of
	 *   read characters
	 *
	 * Remarks:
	 *   The process path is saved on
	 *   'pprocess_path' and needs to
	 *   be free'd
	 */

	mem_size_t read_chars = 0;
	if (!pprocess_path) return read_chars;
#	if   MEM_OS == MEM_WIN
	HMODULE hModule = (HMODULE)INVALID_HANDLE_VALUE;
	hModule = GetModuleHandle(NULL);
	if (!hModule || hModule == INVALID_HANDLE_VALUE) return read_chars;

	*pprocess_path = (mem_tstring_t)malloc((MEM_PATH_MAX + 1) * sizeof(mem_tchar_t));
	if (!*pprocess_path) return read_chars;
	memset(*pprocess_path, 0x0, (MEM_PATH_MAX + 1) * sizeof(mem_tchar_t));

	read_chars = (mem_size_t)GetModuleFileName(hModule, *pprocess_path, MEM_PATH_MAX);
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	read_chars = mem_ex_get_process_path(mem_in_get_pid(), pprocess_path);
#	endif
	return read_chars;
}

LIBMEM_EXTERN mem_arch_t         mem_in_get_arch(mem_void_t)
{
	/*
	 * Description:
	 *   Gets the architecture of
	 *   the caller process
	 *
	 * Return Value:
	 *   Returns the architecture
	 *   of the caller process or
	 *   'MEM_ARCH_UNKNOWN' if the
	 *   architecture is not
	 *   recognized
	 */

	return (mem_arch_t)MEM_ARCH;
}

LIBMEM_EXTERN mem_process_t      mem_in_get_process(mem_void_t)
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

LIBMEM_EXTERN mem_module_t       mem_in_get_module(mem_tstring_t module_ref)
{
	/*
	 * Description:
	 *   Gets information about
	 *   the module 'module_ref' of
	 *   the caller process
	 *
	 * Return Value:
	 *   Returns information about
	 *   the module 'module_ref' or a
	 *   'mem_module_t' filled with
	 *   invalid values on error
	 */

	mem_module_t mod = { 0 };
#	if MEM_OS == MEM_WIN
	MODULEINFO mod_info = { 0 };
	HMODULE hModule = (HMODULE)INVALID_HANDLE_VALUE;
	hModule = GetModuleHandle(module_ref);
	if (!hModule || hModule == INVALID_HANDLE_VALUE) return mod;
	GetModuleInformation(GetCurrentProcess(), hModule, &mod_info, sizeof(mod_info));

	mod.base = (mem_voidptr_t)mod_info.lpBaseOfDll;
	mod.size = (mem_size_t)mod_info.SizeOfImage;
	mod.end  = (mem_voidptr_t)((mem_uintptr_t)mod.base + mod.size);

#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	mod = mem_ex_get_module(mem_in_get_process(), module_ref);
#	endif
	return mod;
}

LIBMEM_EXTERN mem_size_t         mem_in_get_module_name(mem_module_t mod, mem_tstring_t *pmodule_name)
{
	/*
	 * Description:
	 *   Gets the module name of 'mod'
	 *
	 * Return Value:
	 *   Returns the count of
	 *   read characters
	 *
	 * Remarks:
	 *   The module name is saved on
	 *   'pmodule_name' and needs to
	 *   be free'd
	 */

	mem_size_t read_chars = 0;

	mem_tstring_t module_path = (mem_tstring_t)NULL;
	if (mem_in_get_module_path(mod, &module_path))
	{
		mem_tchar_t *p_pos = module_path;
		mem_tchar_t *temp = (mem_tchar_t *)NULL;
#		if   MEM_OS == MEM_WIN
		for (temp = &p_pos[-1]; (temp = MEM_STR_CHR(&temp[1], MEM_STR('\\'))) != NULL; p_pos = &temp[1]);
#		elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
		for (temp = &p_pos[-1]; (temp = MEM_STR_CHR(&temp[1], MEM_STR('/'))) != NULL; p_pos = &temp[1]);
#		endif

		read_chars = MEM_STR_LEN(module_path) - (((uintptr_t)p_pos - (uintptr_t)module_path) / sizeof(mem_tchar_t));
		mem_size_t module_name_size = (read_chars + 1) * sizeof(mem_tchar_t);
		*pmodule_name = (mem_tstring_t)malloc(module_name_size);
		if (*pmodule_name)
		{
			memset(*pmodule_name, 0x0, module_name_size);
			memcpy(*pmodule_name, p_pos, read_chars * sizeof(mem_tchar_t));
		}

		else
		{
			read_chars = 0;
		}

		free(module_path);
	}

	return read_chars;
}

LIBMEM_EXTERN mem_size_t         mem_in_get_module_path(mem_module_t mod, mem_tstring_t *pmodule_path)
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
	HMODULE hModule = (HMODULE)INVALID_HANDLE_VALUE;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPTSTR)mod.base, &hModule);
	if (hModule && hModule != INVALID_HANDLE_VALUE)
	{
		mem_size_t path_size = MEM_PATH_MAX * sizeof(mem_tchar_t);
		*pmodule_path = (mem_tstring_t)malloc(path_size + sizeof(mem_tchar_t));
		if (!*pmodule_path) return read_chars;
		memset(*pmodule_path, 0x0, path_size + sizeof(mem_tchar_t));
		read_chars = (mem_size_t)GetModuleFileName(hModule, *pmodule_path, MEM_PATH_MAX);
	}
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	read_chars = mem_ex_get_module_path(mem_in_get_process(), mod, pmodule_path);
#	endif

	return read_chars;
}

LIBMEM_EXTERN mem_size_t         mem_in_get_module_list(mem_module_t **pmodule_list)
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

LIBMEM_EXTERN mem_page_t         mem_in_get_page(mem_voidptr_t src)
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
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	page = mem_ex_get_page(mem_in_get_process(), src);
#	endif
	return page;
}

LIBMEM_EXTERN mem_bool_t         mem_in_read(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size)
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

	return memcpy(dst, src, size) == (void *)dst ? MEM_TRUE : MEM_FALSE;
}

LIBMEM_EXTERN mem_bool_t         mem_in_write(mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size)
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

	return memcpy(dst, src, size) == (void *)src ? MEM_TRUE : MEM_FALSE;
}

LIBMEM_EXTERN mem_bool_t         mem_in_set(mem_voidptr_t src, mem_byte_t byte, mem_size_t size)
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

	return memset(src, byte, size) == (void *)src ? MEM_TRUE : MEM_FALSE;
}

LIBMEM_EXTERN mem_voidptr_t      mem_in_syscall(mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5)
{
	/*
	 * Description:
	 *   Runs the syscall 'syscall_n' with
	 *   up to 6 arguments (arg0 ... arg5)
	 *
	 * Return Value:
	 *   Returns the value returned by
	 *   the syscall or 'MEM_BAD' on error
	 */

	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD;
#	if   MEM_OS == MEM_WIN
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	ret = (mem_voidptr_t)(mem_uintptr_t)syscall(syscall_n, arg0, arg1, arg2, arg3, arg4, arg5);
#	endif
	return ret;
}

LIBMEM_EXTERN mem_bool_t         mem_in_protect(mem_voidptr_t src, mem_size_t size, mem_prot_t protection, mem_prot_t *pold_protection)
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
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	long page_size = sysconf(_SC_PAGE_SIZE);
	void *src_page = (void *)((uintptr_t)src & -page_size);
	mem_page_t page = mem_in_get_page((mem_voidptr_t)src_page);
	old_protection = page.protection;
	ret = mprotect(src_page, size, protection) == 0 ? MEM_TRUE : MEM_FALSE;
#	endif

	if (pold_protection) *pold_protection = old_protection;

	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_in_allocate(mem_size_t size, mem_prot_t protection)
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
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	alloc = (mem_voidptr_t)mmap(NULL, size, protection, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (alloc == (mem_voidptr_t)MAP_FAILED) alloc = (mem_voidptr_t)MEM_BAD;
#	endif

	return alloc;
}

LIBMEM_EXTERN mem_bool_t         mem_in_deallocate(mem_voidptr_t src, mem_size_t size)
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
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	ret = munmap(src, size) == 0 ? MEM_TRUE : MEM_FALSE;
#	endif

	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_in_scan(mem_data_t data, mem_size_t size, mem_voidptr_t start, mem_voidptr_t stop)
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
	mem_data_t i = (mem_data_t)NULL;
	for (i = (mem_data_t)start; (mem_uintptr_t)&i[size] <= (mem_uintptr_t)stop; i = &i[1])
	{
		mem_int_t found = MEM_TRUE;
		mem_size_t j = (mem_size_t)NULL;
		for (j = 0; j < size; j++)
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

LIBMEM_EXTERN mem_voidptr_t      mem_in_pattern_scan(mem_data_t pattern, mem_tstring_t mask, mem_voidptr_t start, mem_voidptr_t stop)
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
	mem_data_t i = (mem_data_t)NULL;
	for (i = (mem_data_t)start; (mem_uintptr_t)&i[size] <= (mem_uintptr_t)stop; i = &i[1])
	{
		mem_int_t found = MEM_TRUE;
		mem_size_t j = (mem_size_t)NULL;
		for (j = 0; j < size; j++)
		{
			found &= ((mask[j] != MEM_STR('x') && mask[j] != MEM_STR('X')) || i[j] == pattern[j]);

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

LIBMEM_EXTERN mem_size_t         mem_in_detour_size(mem_asm_t method)
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

	if (method >= 0 && method < MEM_ASM_DETOUR_INVALID)
		size = mem_in_payload_size(method);

	return size;
}

LIBMEM_EXTERN mem_size_t         mem_in_payload_size(mem_asm_t method)
{
	/*
	 * Description:
	 *   Gets the size of the payload 'method'
	 *
	 * Return Value:
	 *   Returns the size of the payload 'method'
	 *   or 'MEM_BAD' on error
	 */

	mem_size_t size = (mem_size_t)MEM_BAD;

	if (method >= 0 && method < MEM_ASM_INVALID)
		size = MEM_PAYLOADS[method].size;

	return size;
}

LIBMEM_EXTERN mem_bool_t         mem_in_detour(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_asm_t method, mem_data_t *stolen_bytes)
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
	 *
	 * Remarks:
	 *   'stolen_bytes' (if not null)
	 *   has to be free'd
	 */

	mem_bool_t ret = MEM_FALSE;
	mem_size_t detour_size = mem_in_detour_size(method);
	mem_prot_t protection = 0;

#	if   MEM_OS == MEM_WIN
	protection = PAGE_EXECUTE_READWRITE;
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif

	if (detour_size == (mem_size_t)MEM_BAD || size < detour_size || mem_in_protect(src, size, protection, NULL) == MEM_FALSE) return ret;

	if (stolen_bytes)
	{
		*stolen_bytes = (mem_data_t)malloc(size);
		if (*stolen_bytes)
			mem_in_read(src, (mem_voidptr_t)*stolen_bytes, size);
	}

	mem_data_t detour_buffer = (mem_data_t)malloc(detour_size);
	if (!detour_buffer) return ret;
	mem_in_read((mem_voidptr_t)MEM_PAYLOADS[method].payload, detour_buffer, detour_size);

#	if   MEM_ARCH == _MEM_ARCH_x86_32
	switch (method)
	{
	case MEM_ASM_x86_JMP32:
		*(mem_voidptr_t *)(&detour_buffer[1]) = (mem_voidptr_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		break;
	case MEM_ASM_x86_JMP64:
		*(mem_voidptr_t *)(&detour_buffer[1]) = dst;
		break;
	case MEM_ASM_x86_CALL32:
		*(mem_voidptr_t *)(&detour_buffer[1]) = (mem_voidptr_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		break;
	case MEM_ASM_x86_CALL64:
		*(mem_voidptr_t *)(&detour_buffer[1]) = dst;
		break;
	default:
		break;
	}
#	elif MEM_ARCH == _MEM_ARCH_x86_64
	switch (method)
	{
	case MEM_ASM_x86_JMP32:
		*(mem_voidptr_t *)(&detour_buffer[1]) = (mem_voidptr_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		break;
	case MEM_ASM_x86_JMP64:
		*(mem_voidptr_t *)(&detour_buffer[2]) = dst;
		break;
	case MEM_ASM_x86_CALL32:
		*(mem_voidptr_t *)(&detour_buffer[1]) = (mem_voidptr_t)((mem_uintptr_t)dst - (mem_uintptr_t)src - detour_size);
		break;
	case MEM_ASM_x86_CALL64:
		*(mem_voidptr_t *)(&detour_buffer[2]) = dst;
		break;
	default:
		break;
	}
#	endif

	mem_in_write(src, detour_buffer, detour_size);
	free(detour_buffer);
	ret = MEM_TRUE;

	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_in_detour_trampoline(mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size, mem_asm_t method, mem_data_t *stolen_bytes)
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
	 *
	 * Remarks:
	 *   The gateway returned has to be
	 *   free'd
	 */

	mem_voidptr_t gateway = (mem_voidptr_t)MEM_BAD;

	mem_size_t detour_size = mem_in_detour_size(method);
	mem_prot_t protection = 0;
#	if   MEM_OS == MEM_WIN
	protection = PAGE_EXECUTE_READWRITE;
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
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

LIBMEM_EXTERN mem_bool_t         mem_in_detour_restore(mem_voidptr_t src, mem_data_t stolen_bytes, mem_size_t size)
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
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	protection = PROT_EXEC | PROT_READ | PROT_WRITE;
#	endif

	mem_bool_t ret = MEM_TRUE;

	if (
		mem_in_protect(src, size, protection, NULL)          == MEM_FALSE ||
		mem_in_write(src, (mem_voidptr_t)stolen_bytes, size) == MEM_FALSE
	) ret = MEM_FALSE;

	return ret;
}

LIBMEM_EXTERN mem_module_t       mem_in_load_module(mem_tstring_t path)
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
		mod = mem_in_get_module(path);

#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	if (dlopen(path, RTLD_LAZY))
		mod = mem_in_get_module(path);
#	endif

	return mod;
}

LIBMEM_EXTERN mem_bool_t         mem_in_unload_module(mem_module_t mod)
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
	HMODULE hModule = (HMODULE)INVALID_HANDLE_VALUE;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPTSTR)mod.base, &hModule);
	if (hModule && hModule != INVALID_HANDLE_VALUE)
	{
		FreeLibrary(hModule);
		ret = MEM_TRUE;
	}
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	mem_tstring_t mod_path = (mem_tstring_t)NULL;
	if (mem_in_get_module_path(mod, &mod_path) && dlclose(dlopen(mod_path, RTLD_LAZY)))
		ret = MEM_TRUE;
#	endif

	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_in_get_symbol(mem_module_t mod, mem_cstring_t symbol)
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
	HMODULE hModule = (HMODULE)INVALID_HANDLE_VALUE;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPTSTR)mod.base, &hModule);
	if (hModule && hModule != INVALID_HANDLE_VALUE)
	{
		addr = (mem_voidptr_t)GetProcAddress(hModule, symbol);
		if (!addr) addr = (mem_voidptr_t)MEM_BAD;
	}
#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	mem_tstring_t mod_path = (mem_tstring_t)NULL;
	if (mem_in_get_module_path(mod, &mod_path))
	{
		void *handle = dlopen(mod_path, RTLD_LAZY);
		addr = dlsym(handle, symbol);
		if (!addr) addr = (mem_voidptr_t)MEM_BAD;
	}
#	endif

	return addr;
}

/* mem_ex */

LIBMEM_EXTERN mem_pid_t          mem_ex_get_pid(mem_tstring_t process_ref)
{
	/*
	 * Description:
	 *   Gets the id of
	 *   the process with name/path 'process_ref'
	 *
	 * Return Value:
	 *   Process ID or 'MEM_BAD' on error
	 */

	mem_pid_t pid = (mem_pid_t)MEM_BAD;

#	if   MEM_OS == MEM_WIN
	mem_size_t process_ref_len = MEM_STR_LEN(process_ref);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);

		if (Process32First(hSnap, &entry))
		{
			do
			{
				mem_tstring_t process_path = (mem_tstring_t)NULL;
				mem_size_t    path_len = mem_ex_get_process_path(entry.th32ProcessID, &process_path);
				if (path_len && path_len >= process_ref_len)
				{
					if (!MEM_STR_CMP(&process_path[path_len - process_ref_len], process_ref))
					{
						pid = entry.th32ProcessID;
					}

					free(process_path);

					if (pid != (mem_pid_t)MEM_BAD)
						break;
				}

				if (!MEM_STR_CMP(entry.szExeFile, process_ref))
				{
					pid = entry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &entry));

		}
	}
	CloseHandle(hSnap);
#	elif MEM_OS == MEM_LINUX
	DIR *pdir = opendir("/proc");
	if (!pdir) return pid;
	struct dirent *pdirent;
	while (pid == (mem_pid_t)MEM_BAD && (pdirent = readdir(pdir)))
	{
		mem_pid_t id = (mem_pid_t)atoi(pdirent->d_name);
		if (id != (mem_pid_t)-1 && (id || !MEM_STR_CMP(pdirent->d_name, MEM_STR("0"))))
		{
			mem_tstring_t proc_name = NULL;
			size_t read_chars = mem_ex_get_process_name(id, &proc_name);
			if (read_chars)
			{
				if (!MEM_STR_CMP(process_ref, proc_name))
					pid = id;

				free(proc_name);
				
				if (pid != (mem_pid_t)MEM_BAD)
					break;
			}
		}
	}
	closedir(pdir);
#	elif MEM_OS == MEM_BSD
	kvm_t *kd = kvm_openfiles(NULL, _PATH_DEVNULL, NULL, O_RDONLY, NULL);
	if (kd)
	{
		int proc_count = 0;
		struct kinfo_proc *procs = kvm_getprocs(kd, KERN_PROC_PROC, 0, &proc_count);
		if (procs)
		{
			int proc_it = 0;
			for (proc_it = 0; proc_it < proc_count; ++proc_it)
			{
				struct kinfo_proc *pproc = &procs[proc_it];
				if (pproc && !MEM_STR_CMP(pproc->ki_comm, process_ref))
				{
					pid = pproc->ki_pid;
					break;
				}
			}
			free(procs);
		}
		kvm_close(kd);
	}
#	endif
	
	return pid;
}

LIBMEM_EXTERN mem_size_t         mem_ex_get_process_name(mem_pid_t pid, mem_tstring_t *pprocess_name)
{
	/*
	 * Description:
	 *   Gets the name of
	 *   the process with pid 'pid'
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

	mem_tstring_t process_path = (mem_tstring_t)NULL;
#	if    MEM_OS == MEM_WIN || MEM_OS == MEM_LINUX
	if (mem_ex_get_process_path(pid, &process_path))
	{
		mem_tchar_t *p_pos = process_path;
		mem_tchar_t *temp = (mem_tchar_t *)NULL;
#		if   MEM_OS == MEM_WIN
		for (temp = &p_pos[-1]; (temp = MEM_STR_CHR(&temp[1], MEM_STR('\\'))) != NULL; p_pos = &temp[1]);
#		elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
		for (temp = &p_pos[-1]; (temp = MEM_STR_CHR(&temp[1], MEM_STR('/'))) != NULL; p_pos = &temp[1]);
#		endif

		read_chars = MEM_STR_LEN(process_path) - (((uintptr_t)p_pos - (uintptr_t)process_path) / sizeof(mem_tchar_t));
		mem_size_t process_name_size = (read_chars + 1) * sizeof(mem_tchar_t);
		*pprocess_name = (mem_tstring_t)malloc(process_name_size);
		if (*pprocess_name)
		{
			memset(*pprocess_name, 0x0, process_name_size);
			memcpy(*pprocess_name, p_pos, read_chars * sizeof(mem_tchar_t));
		}

		else
		{
			read_chars = 0;
		}

		free(process_path);
	}
#	elif MEM_OS == MEM_BSD
	kvm_t *kd = kvm_openfiles(NULL, _PATH_DEVNULL, NULL, O_RDONLY, NULL);
	if (kd)
	{
		int proc_count = 0;
		struct kinfo_proc *pproc = kvm_getprocs(kd, KERN_PROC_PID, pid, &proc_count);
		if (pproc && proc_count > 0)
		{
			mem_size_t path_len = MEM_STR_LEN(pproc->ki_comm);
			mem_size_t path_size = (path_len + 1) * sizeof(mem_tchar_t);
			*pprocess_name = (mem_tstring_t)malloc(path_size);
			if (*pprocess_name)
			{
				memcpy(*pprocess_name, pproc->ki_comm, path_size);
				read_chars = path_len;
			}

			free(pproc);
		}
		kvm_close(kd);
	}
#	endif

	return read_chars;
}

LIBMEM_EXTERN mem_size_t         mem_ex_get_process_path(mem_pid_t pid, mem_tstring_t *pprocess_path)
{
	/*
	 * Description:
	 *   Gets the path of
	 *   the process with pid 'pid'
	 *
	 * Return Value:
	 *   Returns the count of
	 *   read characters
	 *
	 * Remarks:
	 *   The process path is saved on
	 *   'pprocess_path' and needs to
	 *   be free'd
	 */

	mem_size_t read_chars = 0;

#	if   MEM_OS == MEM_WIN

	*pprocess_path = (mem_tstring_t)malloc((MEM_PATH_MAX + 1) * sizeof(mem_tchar_t));
	if (!*pprocess_path) return read_chars;
	memset(*pprocess_path, 0x0, (MEM_PATH_MAX + 1) * sizeof(mem_tchar_t));
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
	{
		free(*pprocess_path);
		return read_chars;
	}

	read_chars = GetModuleFileNameEx(hProcess, NULL, *pprocess_path, MEM_PATH_MAX);
	CloseHandle(hProcess);

#	elif MEM_OS == MEM_LINUX
	char path[64] = { 0 };
	snprintf(path, sizeof(path) - sizeof(mem_tchar_t), "/proc/%i/exe", pid);
	*pprocess_path = (mem_tstring_t)malloc((MEM_PATH_MAX + 1) * sizeof(mem_tchar_t));
	if (!*pprocess_path) return read_chars;
	memset(*pprocess_path, 0x0, (MEM_PATH_MAX + 1) * sizeof(mem_tchar_t));
	read_chars = (mem_size_t)(readlink(path, *pprocess_path, MEM_PATH_MAX * sizeof(mem_tchar_t)) / sizeof(mem_tchar_t));
#	elif MEM_OS == MEM_BSD
	struct procstat *ps = procstat_open_sysctl();
	if (ps)
	{
		unsigned int proc_count = 0;
		struct kinfo_proc *pproc = procstat_getprocs(ps, KERN_PROC_PID, pid, &proc_count);
		if (pproc && proc_count > 0)
		{
			mem_tchar_t proc_path[MEM_PATH_MAX] = { 0 };

			if (procstat_getpathname(ps, pproc, proc_path, sizeof(proc_path)) == 0)
			{
				read_chars = MEM_STR_LEN(proc_path);
				mem_size_t path_size = (read_chars + 1) * sizeof(mem_tchar_t);
				*pprocess_path = (mem_tstring_t)malloc(path_size);
				memcpy(*pprocess_path, proc_path, path_size);
			}

			free(pproc);
		}
		procstat_close(ps);
	}
#	endif

	return read_chars;
}

LIBMEM_EXTERN mem_arch_t         mem_ex_get_system_arch(mem_void_t)
{
	/*
	 * Description:
	 *   Gets the architecture of
	 *   the system
	 *
	 * Return Value:
	 *   Returns the architecture of
	 *   the system or 'MEM_ARCH_UNKNOWN'
	 *   on error
	 */

	mem_arch_t arch = MEM_ARCH_UNKNOWN;

#	if   MEM_OS == MEM_WIN
	SYSTEM_INFO sys_info = { 0 };
	GetNativeSystemInfo(&sys_info);
	switch (sys_info.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_INTEL:
		arch = MEM_ARCH_x86_32;
		break;
	case PROCESSOR_ARCHITECTURE_AMD64:
		arch = MEM_ARCH_x86_64;
		break;
	default:
		break;
	}

#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD

	struct utsname utsbuf = { 0 };
	if (uname(&utsbuf) != 0) return arch;

	if      (!MEM_STR_CMP(utsbuf.machine, "x86_32")) arch = MEM_ARCH_x86_32;
	else if (!MEM_STR_CMP(utsbuf.machine, "x86_64")) arch = MEM_ARCH_x86_64;
	else                                             arch = MEM_ARCH_UNKNOWN;

#	endif

	return arch;
}

LIBMEM_EXTERN mem_arch_t         mem_ex_get_arch(mem_pid_t pid)
{
	/*
	 * Description:
	 *   Gets the architecture of
	 *   the process with pid 'pid'
	 *
	 * Return Value:
	 *   Returns the architecture of
	 *   the process or 'MEM_ARCH_UNKNOWN'
	 *   on error
	 */

	mem_arch_t arch = MEM_ARCH_UNKNOWN;
#	if   MEM_OS == MEM_WIN

	BOOL IsWow64 = FALSE;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return arch;
	BOOL Check = IsWow64Process(hProcess, &IsWow64);
	CloseHandle(hProcess);
	if (!Check) return arch;

	mem_arch_t sys_arch = mem_ex_get_system_arch();

	switch (mem_in_get_arch())
	{
	case MEM_ARCH_x86_32:
		if (sys_arch == MEM_ARCH_x86_32)
			arch = MEM_ARCH_x86_32;
		else if (sys_arch == MEM_ARCH_x86_64 && !IsWow64)
			arch = MEM_ARCH_x86_64;
	case MEM_ARCH_x86_64:
		if (IsWow64) arch = MEM_ARCH_x86_32;
		else arch = MEM_ARCH_x86_64;
		break;
	}

#	elif MEM_OS == MEM_LINUX
	arch = (mem_arch_t)MEM_ARCH;
#	elif MEM_OS == MEM_BSD
	struct procstat *ps = procstat_open_sysctl();
	if (ps)
	{
		unsigned int proc_count = 0;
		struct kinfo_proc *pproc = procstat_getprocs(ps, KERN_PROC_PID, pid, &proc_count);
		if (pproc && proc_count > 0)
		{
			if (MEM_STR_STR(pproc->ki_emul, MEM_STR("32"))) arch = MEM_ARCH_x86_32;
			else if (MEM_STR_STR(pproc->ki_emul, MEM_STR("64"))) arch = MEM_ARCH_x86_64;
			else arch = MEM_ARCH_UNKNOWN;
			free(pproc);
		}
		procstat_close(ps);
	}
#	endif

	return arch;
}

LIBMEM_EXTERN mem_process_t      mem_ex_get_process(mem_pid_t pid)
{
	/*
	 * Description:
	 *   Gets information about
	 *   the process with pid 'pid'
	 *
	 * Return Value:
	 *   Returns information about
	 *   the process with pid 'pid' or a
	 *   'mem_process_t' filled with
	 *   invalid values on error
	 */

	mem_process_t process = { 0 };
	process.pid  = pid;
	process.arch = mem_ex_get_arch(process.pid);
	return process;
}

LIBMEM_EXTERN mem_size_t         mem_ex_get_process_list(mem_process_t **pprocess_list)
{
	/*
	 * Description:
	 *   Gets the process list
	 *
	 * Return Value:
	 *   Returns the length of
	 *   the process list buffer
	 *
	 * Remarks:
	 *   The process list is saved on
	 *   'pprocess_list' and needs to
	 *   be free'd
	 */

	mem_size_t count = 0;
	*pprocess_list = (mem_process_t *)malloc(sizeof(mem_process_t));
	if (!*pprocess_list) return count;
#	if   MEM_OS == MEM_WIN
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);

		if (Process32First(hSnap, &entry))
		{
			do
			{
				mem_process_t *holder = *pprocess_list;
				*pprocess_list = (mem_process_t *)malloc((count + 1) * sizeof(mem_process_t));
				if (*pprocess_list)
				{
					memcpy(*pprocess_list, holder, count * sizeof(mem_process_t));
					(*pprocess_list)[count].pid  = (mem_pid_t)entry.th32ProcessID;
					(*pprocess_list)[count].arch = mem_ex_get_arch(entry.th32ProcessID);
				}

				free(holder);

				if (!*pprocess_list)
				{
					count = 0;
					break;
				}

				++count;
			} while (Process32Next(hSnap, &entry));

		}
	}
	CloseHandle(hSnap);
#	elif MEM_OS == MEM_LINUX
	DIR *pdir = opendir("/proc");
	if (pdir)
	{
		struct dirent *pdirent;
		while ((pdirent = readdir(pdir)))
		{
			mem_pid_t id = (mem_pid_t)atoi(pdirent->d_name);
			if (id != (mem_pid_t)-1 && (id || !MEM_STR_CMP(pdirent->d_name, MEM_STR("0"))))
			{
				mem_process_t *holder = *pprocess_list;
				*pprocess_list = (mem_process_t *)malloc((count + 1) * sizeof(mem_process_t));
				if (*pprocess_list)
				{
					memcpy(*pprocess_list, holder, count * sizeof(mem_process_t));
					(*pprocess_list)[count].pid = id;
					(*pprocess_list)[count].arch = mem_ex_get_arch(id);
				}

				free(holder);

				if (!*pprocess_list)
				{
					count = 0;
					break;
				}

				++count;
			}
		}
		closedir(pdir);
	}
#	elif MEM_OS == MEM_BSD
	kvm_t *kd = kvm_openfiles(NULL, _PATH_DEVNULL, NULL, O_RDONLY, NULL);
	if (kd)
	{
		int proc_count = 0;
		struct kinfo_proc *procs = kvm_getprocs(kd, KERN_PROC_PROC, 0, &proc_count);
		if (procs && proc_count > 0)
		{
			for (count = 0; count < proc_count; ++count)
			{
				struct kinfo_proc *pproc = &procs[count];
				if (pproc)
				{
					mem_process_t *holder = *pprocess_list;
					*pprocess_list = (mem_process_t *)malloc((count + 1) * sizeof(mem_process_t));
					if (*pprocess_list)
					{
						memcpy(*pprocess_list, holder, count * sizeof(mem_process_t));
						(*pprocess_list)[count].pid = pproc->ki_pid;
						(*pprocess_list)[count].arch = mem_ex_get_arch(pproc->ki_pid);
					}

					free(holder);

					if (!*pprocess_list)
					{
						count = 0;
						break;
					}
				}
			}
			free(procs);
		}
		kvm_close(kd);
	}
#	endif

	if (count == 0 && *pprocess_list) free(*pprocess_list);

	return count;
}

LIBMEM_EXTERN mem_module_t       mem_ex_get_module(mem_process_t process, mem_tstring_t module_ref)
{
	/*
	 * Description:
	 *   Gets information about
	 *   the module 'module_ref' of
	 *   the process 'process'
	 *
	 * Return Value:
	 *   Returns information about
	 *   the module 'module_ref' or a
	 *   'mem_module_t' filled with
	 *   invalid values on error
	 */

	mem_module_t mod = { 0 };
#	if   MEM_OS == MEM_WIN
	MODULEENTRY32 mod_info = { 0 };
	mod_info.dwSize = sizeof(mod_info);
	mem_size_t ref_len = MEM_STR_LEN(module_ref);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process.pid);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		if (Module32First(hSnap, &entry))
		{
			do
			{
				mem_size_t path_len = MEM_STR_LEN(entry.szExePath);
				if (!MEM_STR_CMP(entry.szModule, module_ref) || (path_len >= ref_len && !MEM_STR_CMP(&entry.szExePath[path_len - ref_len], module_ref)))
				{
					mod_info = entry;
					break;
				}
			} while (Module32Next(hSnap, &entry));
		}

		mod.base = (mem_voidptr_t)mod_info.modBaseAddr;
		mod.size = (mem_size_t)mod_info.modBaseSize;
		mod.end = (mem_voidptr_t)((mem_uintptr_t)mod.base + mod.size);
	}
#	elif MEM_OS == MEM_LINUX
	mem_tchar_t module_str[MEM_PATH_MAX + 1] = { 0 };
	snprintf(module_str, sizeof(module_str) - sizeof(mem_tchar_t), "%s\n", module_ref);
	mem_tchar_t path_buffer[64] = { 0 };
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/maps", process.pid);

	int maps_file = open(path_buffer, O_RDONLY);
	if (maps_file == -1) return mod;
	mem_size_t maps_size = 0;
	mem_tstring_t maps_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(maps_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, maps_buffer, maps_size * sizeof(mem_tchar_t));
		free(maps_buffer);
		maps_buffer = holder;
		maps_buffer[maps_size] = c;
		maps_buffer[maps_size + 1] = '\0';
	}
	close(maps_file);
	if (!maps_buffer) return mod;

	mem_tchar_t *module_base_ptr = MEM_STR_STR(maps_buffer, module_str);
	mem_tchar_t *holder = maps_buffer;
	mem_tchar_t *temp = (mem_tchar_t *)NULL;
	for (temp = &maps_buffer[-1]; (mem_uintptr_t)(temp = MEM_STR_CHR(&temp[1], MEM_STR('\n'))) < (mem_uintptr_t)module_base_ptr && temp; holder = &temp[1]);
	module_base_ptr = holder;

	if (!module_base_ptr) module_base_ptr = maps_buffer;
	mem_tchar_t *module_base_endptr = MEM_STR_CHR(module_base_ptr, MEM_STR('-'));
	if (module_base_endptr)
	{
		mem_tchar_t *module_end_ptr = (mem_tchar_t *)NULL;
		for (temp = &maps_buffer[-1]; (temp = MEM_STR_STR(&temp[1], module_str)) != (mem_tchar_t *)NULL; module_end_ptr = temp);

		if (module_end_ptr)
		{
			holder = maps_buffer;
			for (temp = &maps_buffer[-1]; (mem_uintptr_t)(temp = MEM_STR_STR(&temp[1], module_str)) < (mem_uintptr_t)module_end_ptr && temp; holder = temp);
			module_end_ptr = holder;
			module_end_ptr = &module_end_ptr[MEM_STR_LEN(module_str)];
			module_end_ptr = MEM_STR_CHR(module_end_ptr, MEM_STR('-'));

			if (module_end_ptr)
			{
				module_end_ptr = &module_end_ptr[1];
				mem_tchar_t *module_end_endptr = MEM_STR_CHR(module_end_ptr, MEM_STR(' '));
				if (module_end_endptr)
				{
					mem_tchar_t module_base_str[64] = { 0 };
					memcpy(module_base_str, module_base_ptr, (mem_uintptr_t)module_base_endptr - (mem_uintptr_t)module_base_ptr);

					mem_tchar_t module_end_str[64] = { 0 };
					memcpy(module_end_str, module_end_ptr, (mem_uintptr_t)module_end_endptr - (mem_uintptr_t)module_end_ptr);

					switch (process.arch)
					{
					case MEM_ARCH_x86_32:
						mod.base = (mem_voidptr_t)(mem_uintptr_t)strtoul(module_base_str, NULL, 16);
						mod.end = (mem_voidptr_t)(mem_uintptr_t)strtoul(module_end_str, NULL, 16);
						mod.size = (mem_uintptr_t)mod.end - (mem_uintptr_t)mod.base;
						break;
					case MEM_ARCH_x86_64:
						mod.base = (mem_voidptr_t)(mem_uintptr_t)strtoull(module_base_str, NULL, 16);
						mod.end = (mem_voidptr_t)(mem_uintptr_t)strtoull(module_end_str, NULL, 16);
						mod.size = (mem_uintptr_t)mod.end - (mem_uintptr_t)mod.base;
						break;
					default:
						break;
					}
				}
			}
		}
	}

	free(maps_buffer);
#	elif MEM_OS == MEM_BSD
	mem_tchar_t module_str[MEM_PATH_MAX + 1] = { 0 };
	snprintf(module_str, sizeof(module_str) - sizeof(mem_tchar_t), "%s ", module_ref);
	mem_tchar_t path_buffer[64] = { 0 };
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/map", process.pid);

	int map_file = open(path_buffer, O_RDONLY);
	if (map_file == -1) return mod;
	mem_size_t maps_size = 0;
	mem_tstring_t map_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(map_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, map_buffer, maps_size * sizeof(mem_tchar_t));
		free(map_buffer);
		map_buffer = holder;
		map_buffer[maps_size] = c;
		map_buffer[maps_size + 1] = '\0';
	}
	close(map_file);
	if (!map_buffer) return mod;

	mem_tchar_t *module_base_ptr = MEM_STR_STR(map_buffer, module_str);
	mem_tchar_t *holder = map_buffer;
	mem_tchar_t *temp = (mem_tchar_t *)NULL;
	for (temp = &map_buffer[-1]; (mem_uintptr_t)(temp = MEM_STR_CHR(&temp[1], MEM_STR('\n'))) < (mem_uintptr_t)module_base_ptr && temp; holder = &temp[1]);
	module_base_ptr = holder;
	if (!module_base_ptr) module_base_ptr = map_buffer;
	mem_tchar_t *module_base_endptr = MEM_STR_STR(module_base_ptr, MEM_STR(" 0x"));
	if (module_base_endptr)
	{
		mem_tchar_t *module_end_ptr = (mem_tchar_t *)NULL;
		for (temp = &map_buffer[-1]; (temp = MEM_STR_STR(&temp[1], module_str)) != (mem_tchar_t *)NULL; module_end_ptr = temp);

		if (module_end_ptr)
		{
			holder = map_buffer;
			for (temp = &map_buffer[-1]; (mem_uintptr_t)(temp = MEM_STR_CHR(&temp[1], MEM_STR('\n'))) < (mem_uintptr_t)module_end_ptr && temp; holder = temp);
			module_end_ptr = holder;
			module_end_ptr = MEM_STR_STR(module_end_ptr, MEM_STR(" 0x"));

			if (module_end_ptr)
			{
				module_base_ptr = &module_base_ptr[2];
				module_end_ptr = &module_end_ptr[3];
				mem_tchar_t *module_end_endptr = MEM_STR_CHR(module_end_ptr, MEM_STR(' '));
				if (module_end_endptr)
				{
					mem_tchar_t module_base_str[64] = { 0 };
					memcpy(module_base_str, module_base_ptr, (mem_uintptr_t)module_base_endptr - (mem_uintptr_t)module_base_ptr);

					mem_tchar_t module_end_str[64] = { 0 };
					memcpy(module_end_str, module_end_ptr, (mem_uintptr_t)module_end_endptr - (mem_uintptr_t)module_end_ptr);

					switch (process.arch)
					{
					case MEM_ARCH_x86_32:
						mod.base = (mem_voidptr_t)(mem_uintptr_t)strtoul(module_base_str, NULL, 16);
						mod.end = (mem_voidptr_t)(mem_uintptr_t)strtoul(module_end_str, NULL, 16);
						mod.size = (mem_uintptr_t)mod.end - (mem_uintptr_t)mod.base;
						break;
					case MEM_ARCH_x86_64:
						mod.base = (mem_voidptr_t)(mem_uintptr_t)strtoull(module_base_str, NULL, 16);
						mod.end = (mem_voidptr_t)(mem_uintptr_t)strtoull(module_end_str, NULL, 16);
						mod.size = (mem_uintptr_t)mod.end - (mem_uintptr_t)mod.base;
						break;
					default:
						break;
					}
				}
			}
		}
	}
	free(map_buffer);
#	endif

	return mod;
}

LIBMEM_EXTERN mem_size_t         mem_ex_get_module_name(mem_process_t process, mem_module_t mod, mem_tstring_t *pmodule_name)
{
	/*
	 * Description:
	 *   Gets the module name of 'mod'
	 *   on process 'process'
	 *
	 * Return Value:
	 *   Returns the count of
	 *   read characters
	 *
	 * Remarks:
	 *   The module name is saved on
	 *   'pmodule_name' and needs to
	 *   be free'd
	 */

	mem_size_t read_chars = 0;

	mem_tstring_t module_path = (mem_tstring_t)NULL;
	if (mem_ex_get_module_path(process, mod, &module_path))
	{
		mem_tchar_t *p_pos = module_path;
		mem_tchar_t *temp = (mem_tchar_t *)NULL;
#		if   MEM_OS == MEM_WIN
		for (temp = &p_pos[-1]; (temp = MEM_STR_CHR(&temp[1], MEM_STR('\\'))) != NULL; p_pos = &temp[1]);
#		elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
		for (temp = &p_pos[-1]; (temp = MEM_STR_CHR(&temp[1], MEM_STR('/'))) != NULL; p_pos = &temp[1]);
#		endif

		read_chars = MEM_STR_LEN(module_path) - (((uintptr_t)p_pos - (uintptr_t)module_path) / sizeof(mem_tchar_t));
		mem_size_t module_name_size = (read_chars + 1) * sizeof(mem_tchar_t);
		*pmodule_name = (mem_tstring_t)malloc(module_name_size);
		if (*pmodule_name)
		{
			memset(*pmodule_name, 0x0, module_name_size);
			memcpy(*pmodule_name, p_pos, read_chars * sizeof(mem_tchar_t));
		}

		else
		{
			read_chars = 0;
		}

		free(module_path);
	}

	return read_chars;
}

LIBMEM_EXTERN mem_size_t         mem_ex_get_module_path(mem_process_t process, mem_module_t mod, mem_tstring_t *pmodule_path)
{
	/*
	 * Description:
	 *   Gets the module path of module 'mod'
	 *   on process 'process'
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
	
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process.pid);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		if (Module32First(hSnap, &entry))
		{
			do
			{
				mem_size_t path_len = MEM_STR_LEN(entry.szExePath);
				if (entry.modBaseAddr == mod.base)
				{
					*pmodule_path = (mem_tstring_t)malloc((path_len + 1) * sizeof(mem_tchar_t));
					if (!*pmodule_path) return read_chars;
					memset(*pmodule_path, 0x0, (path_len + 1) * sizeof(mem_tchar_t));
					memcpy(*pmodule_path, entry.szExePath, path_len * sizeof(mem_tchar_t));
					read_chars = path_len;
					return read_chars;
				}

			} while (Module32Next(hSnap, &entry));
		}
	}
#	elif MEM_OS == MEM_LINUX
	mem_tchar_t page_base_str[64] = { 0 };
	mem_tchar_t *page_base = (mem_tchar_t *)MEM_BAD;

	switch (process.arch)
	{
	case MEM_ARCH_x86_32:
		snprintf(page_base_str, sizeof(page_base_str) - sizeof(mem_tchar_t), "%x-", (mem_uint32_t)(mem_uintptr_t)mod.base);
		break;
	case MEM_ARCH_x86_64:
		snprintf(page_base_str, sizeof(page_base_str) - sizeof(mem_tchar_t), (MEM_ARCH == MEM_ARCH_x86_32 ? "%llx-" : "%lx-"), (mem_uint64_t)(mem_uintptr_t)mod.base);
		break;
	default:
		return read_chars;
	}

	mem_tchar_t path_buffer[64 + 1] = { 0 };
	memset(path_buffer, 0x0, sizeof(path_buffer));
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/maps", process.pid);

	int maps_file = open(path_buffer, O_RDONLY);
	if (maps_file == -1) return read_chars;
	mem_size_t maps_size = 0;
	mem_tstring_t maps_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(maps_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, maps_buffer, maps_size * sizeof(mem_tchar_t));
		free(maps_buffer);
		maps_buffer = holder;
		maps_buffer[maps_size] = c;
		maps_buffer[maps_size + 1] = '\0';
	}
	close(maps_file);
	if (!maps_buffer) return read_chars;

	mem_tchar_t *temp = (mem_tchar_t *)NULL;
	for (temp = &maps_buffer[-1]; (temp = MEM_STR_STR(&temp[1], page_base_str)) != (mem_tchar_t *)NULL; page_base = temp);

	if (page_base && page_base != (mem_tchar_t *)MEM_BAD)
	{
		mem_tchar_t *module_path_ptr = page_base;
		module_path_ptr = MEM_STR_CHR(module_path_ptr, MEM_STR('/'));
		if (module_path_ptr)
		{
			mem_tchar_t *module_path_endptr = module_path_ptr;
			module_path_endptr = MEM_STR_CHR(module_path_endptr, MEM_STR('\n'));
			if (module_path_endptr)
			{
				mem_size_t module_path_size = (mem_size_t)((mem_uintptr_t)module_path_endptr - (mem_uintptr_t)module_path_ptr);
				*pmodule_path = (mem_tstring_t)malloc(module_path_size + (1 * sizeof(mem_tchar_t)));
				memset(*pmodule_path, 0x0, module_path_size + (1 * sizeof(mem_tchar_t)));
				memcpy(*pmodule_path, module_path_ptr, module_path_size);
				read_chars = module_path_size / sizeof(mem_tchar_t);
			}
		}
	}

	free(maps_buffer);
#	elif MEM_OS == MEM_BSD
	mem_tchar_t page_base_str[64] = { 0 };
	mem_tchar_t *page_base = (mem_tchar_t *)MEM_BAD;

	switch (process.arch)
	{
	case MEM_ARCH_x86_32:
		snprintf(page_base_str, sizeof(page_base_str) - sizeof(mem_tchar_t), "0x%x ", (mem_uint32_t)(mem_uintptr_t)mod.base);
		break;
	case MEM_ARCH_x86_64:
		snprintf(page_base_str, sizeof(page_base_str) - sizeof(mem_tchar_t), (MEM_ARCH == MEM_ARCH_x86_32 ? "0x%llx " : "0x%lx "), (mem_uint64_t)(mem_uintptr_t)mod.base);
		break;
	default:
		return read_chars;
	}

	mem_tchar_t path_buffer[64 + 1] = { 0 };
	memset(path_buffer, 0x0, sizeof(path_buffer));
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/map", process.pid);

	int map_file = open(path_buffer, O_RDONLY);
	if (map_file == -1) return read_chars;
	mem_size_t maps_size = 0;
	mem_tstring_t map_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(map_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, map_buffer, maps_size * sizeof(mem_tchar_t));
		free(map_buffer);
		map_buffer = holder;
		map_buffer[maps_size] = c;
		map_buffer[maps_size + 1] = '\0';
	}
	close(map_file);
	if (!map_buffer) return read_chars;

	mem_tchar_t *temp = (mem_tchar_t *)NULL;
	for (temp = &map_buffer[-1]; (temp = MEM_STR_STR(&temp[1], page_base_str)) != (mem_tchar_t *)NULL; page_base = temp);

	if (page_base && page_base != (mem_tchar_t *)MEM_BAD)
	{
		mem_tchar_t *module_path_ptr = page_base;
		module_path_ptr = MEM_STR_CHR(module_path_ptr, MEM_STR('/'));
		if (module_path_ptr)
		{
			mem_tchar_t *module_path_endptr = module_path_ptr;
			mem_tchar_t *holder = module_path_endptr;
			module_path_endptr = MEM_STR_CHR(module_path_endptr, MEM_STR('\n'));
			for (temp = module_path_ptr; (mem_uintptr_t)(temp = MEM_STR_CHR(&temp[1], MEM_STR('/'))) < (mem_uintptr_t)module_path_endptr && temp; holder = &temp[1]);
			module_path_endptr = holder;
			module_path_endptr = MEM_STR_CHR(module_path_endptr, MEM_STR(' '));
			if (module_path_endptr)
			{
				mem_size_t module_path_size = (mem_size_t)((mem_uintptr_t)module_path_endptr - (mem_uintptr_t)module_path_ptr);
				*pmodule_path = (mem_tstring_t)malloc(module_path_size + (1 * sizeof(mem_tchar_t)));
				memset(*pmodule_path, 0x0, module_path_size + (1 * sizeof(mem_tchar_t)));
				memcpy(*pmodule_path, module_path_ptr, module_path_size);
				read_chars = module_path_size / sizeof(mem_tchar_t);
			}
		}
	}

	free(map_buffer);
#	endif

	return read_chars;
}

LIBMEM_EXTERN mem_size_t         mem_ex_get_module_list(mem_process_t process, mem_module_t **pmodule_list)
{
	/*
	 * Description:
	 *   Gets the module list of
	 *   the process 'process'
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

	mem_size_t count = 0;
	*pmodule_list = (mem_module_t *)malloc(sizeof(mem_module_t));

#	if   MEM_OS == MEM_WIN
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process.pid);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		if (Module32First(hSnap, &entry))
		{
			do
			{
				mem_module_t *holder = *pmodule_list;
				*pmodule_list = (mem_module_t *)malloc((count + 1) * sizeof(mem_module_t));
				if (*pmodule_list)
					memcpy(*pmodule_list, holder, count * sizeof(mem_module_t));

				free(holder);

				if (!*pmodule_list)
				{
					count = 0;
					break;
				}

				mem_module_t mod = { 0 };
				mod.base = (mem_voidptr_t)entry.modBaseAddr;
				mod.size = (mem_size_t)entry.modBaseSize;
				mod.end = (mem_voidptr_t)((mem_uintptr_t)mod.base + mod.size);

				(*pmodule_list)[count] = mod;
				++count;

			} while (Module32Next(hSnap, &entry));
		}
	}
#	elif MEM_OS == MEM_LINUX

	mem_tchar_t path_buffer[64 + 1] = { 0 };
	memset(path_buffer, 0x0, sizeof(path_buffer));
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/maps", process.pid);

	int maps_file = open(path_buffer, O_RDONLY);
	if (maps_file == -1) return count;
	mem_size_t maps_size = 0;
	mem_tstring_t maps_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(maps_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, maps_buffer, maps_size * sizeof(mem_tchar_t));
		free(maps_buffer);
		maps_buffer = holder;
		maps_buffer[maps_size] = c;
		maps_buffer[maps_size + 1] = '\0';
	}
	close(maps_file);
	if (!maps_buffer) return count;

	mem_tchar_t *module_path_ptr = maps_buffer;
	mem_tchar_t *module_path_endptr = maps_buffer;

	*pmodule_list = (mem_module_t *)malloc(sizeof(mem_module_t));

	while ((module_path_ptr = MEM_STR_CHR(module_path_endptr, MEM_STR('/'))) != NULL)
	{
		module_path_endptr = MEM_STR_CHR(module_path_ptr, MEM_STR('\n'));
		if (!module_path_endptr) break;

		mem_module_t mod = { 0 };
		mem_size_t module_path_size = (mem_size_t)((mem_uintptr_t)module_path_endptr - (mem_uintptr_t)module_path_ptr);
		mem_tstring_t module_str = (mem_tstring_t)malloc(module_path_size + (1 * sizeof(mem_tchar_t)));
		memset(module_str, 0x0, module_path_size + (1 * sizeof(mem_tchar_t)));
		memcpy(module_str, module_path_ptr, module_path_size);

		mem_tchar_t *module_base_ptr = MEM_STR_STR(maps_buffer, module_str);
		mem_tchar_t *holder = maps_buffer;
		mem_tchar_t *temp = (mem_tchar_t *)NULL;
		for (temp = &maps_buffer[-1]; (mem_uintptr_t)(temp = MEM_STR_CHR(&temp[1], MEM_STR('\n'))) < (mem_uintptr_t)module_base_ptr && temp; holder = &temp[1]);
		module_base_ptr = holder;

		if (!module_base_ptr) module_base_ptr = maps_buffer;
		mem_tchar_t *module_base_endptr = MEM_STR_CHR(module_base_ptr, MEM_STR('-'));
		if (module_base_endptr)
		{
			mem_tchar_t *module_end_ptr = (mem_tchar_t *)NULL;
			for (temp = &maps_buffer[-1]; (temp = MEM_STR_STR(&temp[1], module_str)) != (mem_tchar_t *)NULL; module_end_ptr = temp);

			if (module_end_ptr)
			{
				holder = maps_buffer;
				for (temp = &maps_buffer[-1]; (mem_uintptr_t)(temp = MEM_STR_STR(&temp[1], module_str)) < (mem_uintptr_t)module_end_ptr && temp; holder = temp);
				module_end_ptr = holder;
				module_end_ptr = &module_end_ptr[MEM_STR_LEN(module_str)];
				module_end_ptr = MEM_STR_CHR(module_end_ptr, MEM_STR('-'));

				if (module_end_ptr)
				{
					module_end_ptr = &module_end_ptr[1];
					mem_tchar_t *module_end_endptr = MEM_STR_CHR(module_end_ptr, MEM_STR(' '));
					if (module_end_endptr)
					{
						mem_tchar_t module_base_str[64] = { 0 };
						memcpy(module_base_str, module_base_ptr, (mem_uintptr_t)module_base_endptr - (mem_uintptr_t)module_base_ptr);

						mem_tchar_t module_end_str[64] = { 0 };
						memcpy(module_end_str, module_end_ptr, (mem_uintptr_t)module_end_endptr - (mem_uintptr_t)module_end_ptr);

						if (process.arch >= 0 && process.arch < MEM_ARCH_UNKNOWN)
						{
							switch (process.arch)
							{
							case MEM_ARCH_x86_32:
								mod.base = (mem_voidptr_t)(mem_uintptr_t)strtoul(module_base_str, NULL, 16);
								mod.end = (mem_voidptr_t)(mem_uintptr_t)strtoul(module_end_str, NULL, 16);
								mod.size = (mem_uintptr_t)mod.end - (mem_uintptr_t)mod.base;
								break;
							case MEM_ARCH_x86_64:
								mod.base = (mem_voidptr_t)(mem_uintptr_t)strtoull(module_base_str, NULL, 16);
								mod.end = (mem_voidptr_t)(mem_uintptr_t)strtoull(module_end_str, NULL, 16);
								mod.size = (mem_uintptr_t)mod.end - (mem_uintptr_t)mod.base;
								break;
							default:
								break;
							}

							mem_module_t *list_holder = *pmodule_list;
							*pmodule_list = (mem_module_t *)malloc((count + 1) * sizeof(mem_module_t));
							if (*pmodule_list)
							{
								memcpy(*pmodule_list, list_holder, count * sizeof(mem_module_t));
								(*pmodule_list)[count] = mod;
							}
							
							free(list_holder);

							if (!*pmodule_list)
							{
								count = 0;
								break;
							}

							++count;

							module_path_endptr = module_end_endptr;
							module_path_endptr = MEM_STR_CHR(module_path_endptr, MEM_STR('\n'));
							if (!module_path_endptr) break;
						}
					}
				}
			}
		}
	}

	free(maps_buffer);
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	if (count == 0 && *pmodule_list) free(*pmodule_list);
	return count;
}

LIBMEM_EXTERN mem_page_t         mem_ex_get_page(mem_process_t process, mem_voidptr_t src)
{
	/*
	 * Description:
	 *   Gets information about the
	 *   page 'src' is in from  the
	 *   process 'process'
	 *
	 * Return Value:
	 *   Returns information about the
	 *   page 'src' is in or a 'page_t'
	 *   filled with invalid values
	 */

	mem_page_t page = { 0 };

#	if   MEM_OS == MEM_WIN
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return page;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	VirtualQueryEx(hProcess, src, &mbi, sizeof(mbi));
	CloseHandle(hProcess);
	page.base = mbi.BaseAddress;
	page.size = mbi.RegionSize;
	page.end = (mem_voidptr_t)((mem_uintptr_t)page.base + page.size);
	page.protection = mbi.Protect;
	page.flags = mbi.Type;
#	elif MEM_OS == MEM_LINUX
	long page_size = sysconf(_SC_PAGE_SIZE);
	src = (mem_voidptr_t)((mem_uintptr_t)src & -page_size);

	mem_tchar_t page_base_str[64] = { 0 };
	mem_tchar_t *page_base = (mem_tchar_t *)MEM_BAD;
	mem_tchar_t *page_end = (mem_tchar_t *)MEM_BAD;

	switch (process.arch)
	{
	case MEM_ARCH_x86_32:
		snprintf(page_base_str, sizeof(page_base_str) - sizeof(mem_tchar_t), "%x-", (mem_uint32_t)(mem_uintptr_t)src);
		break;
	case MEM_ARCH_x86_64:
		snprintf(page_base_str, sizeof(page_base_str) - sizeof(mem_tchar_t), (MEM_ARCH == MEM_ARCH_x86_32 ? "%llx-" : "%lx-"), (mem_uint64_t)(mem_uintptr_t)src);
		break;
	default:
		return page;
	}

	mem_tchar_t path_buffer[64 + 1] = { 0 };
	memset(path_buffer, 0x0, sizeof(path_buffer));
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/maps", process.pid);

	int maps_file = open(path_buffer, O_RDONLY);
	if (maps_file == -1) return page;
	mem_size_t maps_size = 0;
	mem_tstring_t maps_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(maps_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, maps_buffer, maps_size * sizeof(mem_tchar_t));
		free(maps_buffer);
		maps_buffer = holder;
		maps_buffer[maps_size] = c;
		maps_buffer[maps_size + 1] = '\0';
	}
	close(maps_file);
	if (!maps_buffer) return page;

	page_base = MEM_STR_STR(maps_buffer, page_base_str);

	if (page_base && page_base != (mem_tchar_t *)MEM_BAD)
	{
		page_end = MEM_STR_CHR(page_base, MEM_STR('-')) + (1 * sizeof(mem_tchar_t));

		if (page_end && page_end != (mem_tchar_t *)MEM_BAD)
		{
			mem_tchar_t *holder = MEM_STR_CHR(page_end, MEM_STR(' '));

			if (holder)
			{
				holder = &holder[1];

				mem_size_t i = (mem_size_t)NULL;
				for (i = 0; i < 4; i++)
				{
					switch (holder[i])
					{
					case MEM_STR('r'):
						page.protection |= PROT_READ;
						break;
					case MEM_STR('w'):
						page.protection |= PROT_WRITE;
						break;
					case MEM_STR('x'):
						page.protection |= PROT_EXEC;
						break;
					case MEM_STR('p'):
						page.flags = MAP_PRIVATE;
						break;
					case MEM_STR('s'):
						page.flags = MAP_SHARED;
						break;
					default:
						break;
					}
				}

				mem_tchar_t page_base_addr[64] = { 0 };
				memcpy(page_base_addr, page_base, (uintptr_t)page_end - (uintptr_t)page_base);
				mem_tchar_t page_end_addr[64] = { 0 };
				memcpy(page_end_addr, page_end, (uintptr_t)holder - (uintptr_t)page_end);

				switch (process.arch)
				{
				case MEM_ARCH_x86_32:
					page.base = (mem_voidptr_t)(mem_uintptr_t)strtoul(page_base_addr, NULL, 16);
					page.end = (mem_voidptr_t)(mem_uintptr_t)strtoul(page_end_addr, NULL, 16);
					page.size = (mem_uintptr_t)page.end - (mem_uintptr_t)page.base;
					break;
				case MEM_ARCH_x86_64:
					page.base = (mem_voidptr_t)(mem_uintptr_t)strtoull(page_base_addr, NULL, 16);
					page.end = (mem_voidptr_t)(mem_uintptr_t)strtoull(page_end_addr, NULL, 16);
					page.size = (mem_uintptr_t)page.end - (mem_uintptr_t)page.base;
					break;
				default:
					break;
				}
			}
		}
	}

	free(maps_buffer);
#	elif MEM_OS == MEM_BSD
	long page_size = sysconf(_SC_PAGE_SIZE);
	src = (mem_voidptr_t)((mem_uintptr_t)src & -page_size);

	mem_tchar_t page_base_str[64] = { 0 };
	mem_tchar_t *page_base = (mem_tchar_t *)MEM_BAD;
	mem_tchar_t *page_end = (mem_tchar_t *)MEM_BAD;

	switch (process.arch)
	{
	case MEM_ARCH_x86_32:
		snprintf(page_base_str, sizeof(page_base_str) - sizeof(mem_tchar_t), "0x%x ", (mem_uint32_t)(mem_uintptr_t)src);
		break;
	case MEM_ARCH_x86_64:
		snprintf(page_base_str, sizeof(page_base_str) - sizeof(mem_tchar_t), (MEM_ARCH == MEM_ARCH_x86_32 ? "0x%llx " : "0x%lx "), (mem_uint64_t)(mem_uintptr_t)src);
		break;
	default:
		return page;
	}

	mem_tchar_t path_buffer[64 + 1] = { 0 };
	memset(path_buffer, 0x0, sizeof(path_buffer));
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/map", process.pid);

	int map_file = open(path_buffer, O_RDONLY);
	if (map_file == -1) return page;
	mem_size_t maps_size = 0;
	mem_tstring_t map_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(map_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, map_buffer, maps_size * sizeof(mem_tchar_t));
		free(map_buffer);
		map_buffer = holder;
		map_buffer[maps_size] = c;
		map_buffer[maps_size + 1] = '\0';
	}
	close(map_file);
	if (!map_buffer) return page;

	page_base = MEM_STR_STR(map_buffer, page_base_str);

	if (page_base && page_base != (mem_tchar_t *)MEM_BAD)
	{
		page_end = MEM_STR_STR(page_base, MEM_STR(" 0x")) + (1 * sizeof(mem_tchar_t));

		if (page_end && page_end != (mem_tchar_t *)MEM_BAD)
		{
			mem_tchar_t *holder = MEM_STR_CHR(page_end, MEM_STR(' '));
			mem_tchar_t *page_end_endptr = holder;

			int space_count = 1;
			for (space_count = 1; space_count < 5; ++space_count)
				holder = MEM_STR_CHR(holder, MEM_STR(' '));

			if (holder)
			{
				holder = &holder[1];

				mem_size_t i = (mem_size_t)NULL;
				for (i = 0; i < 3; i++)
				{
					switch (holder[i])
					{
					case MEM_STR('r'):
						page.protection |= PROT_READ;
						break;
					case MEM_STR('w'):
						page.protection |= PROT_WRITE;
						break;
					case MEM_STR('x'):
						page.protection |= PROT_EXEC;
						break;
					default:
						break;
					}
				}

				page_base = &page_base[2];
				page_end = &page_end[2];
				mem_tchar_t page_base_addr[64] = { 0 };
				memcpy(page_base_addr, page_base, (mem_uintptr_t)page_end - (mem_uintptr_t)page_base);
				mem_tchar_t page_end_addr[64] = { 0 };
				memcpy(page_end_addr, page_end, (mem_uintptr_t)page_end_endptr - (mem_uintptr_t)page_end);

				switch (process.arch)
				{
				case MEM_ARCH_x86_32:
					page.base = (mem_voidptr_t)(mem_uintptr_t)strtoul(page_base_addr, NULL, 16);
					page.end = (mem_voidptr_t)(mem_uintptr_t)strtoul(page_end_addr, NULL, 16);
					page.size = (mem_uintptr_t)page.end - (mem_uintptr_t)page.base;
					break;
				case MEM_ARCH_x86_64:
					page.base = (mem_voidptr_t)(mem_uintptr_t)strtoull(page_base_addr, NULL, 16);
					page.end = (mem_voidptr_t)(mem_uintptr_t)strtoull(page_end_addr, NULL, 16);
					page.size = (mem_uintptr_t)page.end - (mem_uintptr_t)page.base;
					break;
				default:
					break;
				}
			}
		}
	}

	free(map_buffer);
#	endif

	return page;
}

LIBMEM_EXTERN mem_bool_t         mem_ex_is_process_running(mem_process_t process)
{
	/*
	 * Description:
	 *   Checks if the process 'process'
	 *   is running or not
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' if the process
	 *   is running or 'MEM_FALSE' if not
	 */

	mem_bool_t ret = MEM_FALSE;

#	if   MEM_OS == MEM_WIN
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return ret;
	DWORD ExitCode = 0;
	GetExitCodeProcess(hProcess, &ExitCode);
	CloseHandle(hProcess);
	ret = ExitCode == STILL_ACTIVE ? MEM_TRUE : MEM_FALSE;
#	elif MEM_OS == MEM_LINUX
	struct stat sb;
	char path_buffer[64] = { 0 };
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i", process.pid);
	stat(path_buffer, &sb);
	ret = S_ISDIR(sb.st_mode) ? MEM_TRUE : MEM_FALSE;
#	elif MEM_OS == MEM_BSD
	struct procstat *ps = procstat_open_sysctl();
	if (ps)
	{
		unsigned int proc_count = 0;
		struct kinfo_proc *pproc = procstat_getprocs(ps, KERN_PROC_PID, process.pid, &proc_count);
		if (pproc && proc_count > 0)
		{
			ret = MEM_TRUE;
			free(pproc);
		}
		procstat_close(ps);
	}
#	endif

	return ret;
}

LIBMEM_EXTERN mem_bool_t         mem_ex_read(mem_process_t process, mem_voidptr_t src, mem_voidptr_t dst, mem_size_t size)
{
	/*
	 * Description:
	 *   Reads 'size' bytes from
	 *   'src' and saves them into
	 *   'dst' from process 'process'
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
#	if   MEM_OS == MEM_WIN
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return ret;
	ret = ReadProcessMemory(hProcess, (LPCVOID)src, (LPVOID)dst, (SIZE_T)size, NULL) != 0 ? MEM_TRUE : MEM_FALSE;
	CloseHandle(hProcess);
#	elif MEM_OS == MEM_LINUX
	struct iovec iosrc = { 0 };
	struct iovec iodst = { 0 };
	iodst.iov_base = dst;
	iodst.iov_len  = size;
	iosrc.iov_base = src;
	iosrc.iov_len  = size;
	ret = (mem_size_t)process_vm_readv(process.pid, &iodst, 1, &iosrc, 1, 0) == size ? MEM_TRUE : MEM_FALSE;
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	return ret;
}

LIBMEM_EXTERN mem_bool_t         mem_ex_write(mem_process_t process, mem_voidptr_t dst, mem_voidptr_t src, mem_size_t size)
{
	/*
	 * Description:
	 *   Writes 'size' bytes from
	 *   'src' and saves them into
	 *   'dst' from process 'process'
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
#	if   MEM_OS == MEM_WIN
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return ret;
	ret = WriteProcessMemory(hProcess, dst, (LPCVOID)src, size, NULL) != 0 ? MEM_TRUE : MEM_FALSE;
	CloseHandle(hProcess);
#	elif MEM_OS == MEM_LINUX
	struct iovec iosrc = { 0 };
	struct iovec iodst = { 0 };
	iosrc.iov_base = src;
	iosrc.iov_len = size;
	iodst.iov_base = dst;
	iodst.iov_len = size;
	ret = (mem_size_t)process_vm_writev(process.pid, &iosrc, 1, &iodst, 1, 0) == size ? MEM_TRUE : MEM_FALSE;
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	return ret;
}

LIBMEM_EXTERN mem_bool_t         mem_ex_set(mem_process_t process, mem_voidptr_t dst, mem_byte_t byte, mem_size_t size)
{
	/*
	 * Description:
	 *   Writes 'size' bytes of
	 *   value 'byte' into 'dst'
	 *   from process 'process'
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
	mem_byte_t *data = (mem_byte_t *)malloc(size);
	if (!data) return ret;
	mem_in_set(data, byte, size);
	ret = mem_ex_write(process, dst, data, size);
	free(data);
	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_ex_syscall(mem_process_t process, mem_int_t syscall_n, mem_voidptr_t arg0, mem_voidptr_t arg1, mem_voidptr_t arg2, mem_voidptr_t arg3, mem_voidptr_t arg4, mem_voidptr_t arg5)
{
	/*
	 * Description:
	 *   Runs the syscall 'syscall_n' with
	 *   up to 6 arguments (arg0 ... arg5)
	 *   on the process 'process'
	 *
	 * Return Value:
	 *   Returns the value returned by
	 *   the syscall or 'MEM_BAD' on error
	 */

	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD;

#	if   MEM_OS == MEM_WIN
#	elif MEM_OS == MEM_LINUX

	int status;
	struct user_regs_struct old_regs, regs;
	mem_voidptr_t injection_addr = (mem_voidptr_t)MEM_BAD;
	mem_payload_t injection_buf = { 0 };
	mem_uintptr_t old_data = 0; /* 'word-sized buffer' to store reads from ptrace */
	mem_uintptr_t inj_data = 0; /* 'word-sized buffer' to be used on ptrace for writing */

	switch (process.arch)
	{
	case MEM_ARCH_x86_32:
		injection_buf = MEM_PAYLOADS[MEM_ASM_x86_SYSCALL32];
		break;
	case MEM_ARCH_x86_64:
		injection_buf = MEM_PAYLOADS[MEM_ASM_x86_SYSCALL64];
		break;
	default:
		return ret;
	}

	memcpy(&inj_data, injection_buf.payload, sizeof(inj_data));

	ptrace(PTRACE_ATTACH, process.pid, NULL, NULL);
	wait(&status);

	ptrace(PTRACE_GETREGS, process.pid, NULL, &old_regs);
	regs = old_regs;

#	if   MEM_ARCH == _MEM_ARCH_x86_32
	regs.eax = (mem_uintptr_t)syscall_n;
	regs.ebx = (mem_uintptr_t)arg0;
	regs.ecx = (mem_uintptr_t)arg1;
	regs.edx = (mem_uintptr_t)arg2;
	regs.esi = (mem_uintptr_t)arg3;
	regs.edi = (mem_uintptr_t)arg4;
	regs.ebp = (mem_uintptr_t)arg5;
	injection_addr = (mem_voidptr_t)regs.eip;
#	elif MEM_ARCH == _MEM_ARCH_x86_64
	regs.rax = (mem_uintptr_t)syscall_n;
	regs.rdi = (mem_uintptr_t)arg0;
	regs.rsi = (mem_uintptr_t)arg1;
	regs.rdx = (mem_uintptr_t)arg2;
	regs.r10 = (mem_uintptr_t)arg3;
	regs.r8  = (mem_uintptr_t)arg4;
	regs.r9  = (mem_uintptr_t)arg5;
	injection_addr = (mem_voidptr_t)regs.rip;
#	endif

	old_data = (mem_uintptr_t)ptrace(PTRACE_PEEKDATA, process.pid, (void *)((mem_uintptr_t)injection_addr), NULL);
	ptrace(PTRACE_POKEDATA, process.pid, (void *)((mem_uintptr_t)injection_addr), inj_data);

	ptrace(PTRACE_SETREGS, process.pid, NULL, &regs);
	ptrace(PTRACE_SINGLESTEP, process.pid, NULL, NULL);
	waitpid(process.pid, &status, WSTOPPED);
	ptrace(PTRACE_GETREGS, process.pid, NULL, &regs);
#   if   MEM_ARCH == _MEM_ARCH_x86_32
	ret = (mem_voidptr_t)regs.eax;
#   elif MEM_ARCH == _MEM_ARCH_x86_64
	ret = (mem_voidptr_t)regs.rax;
#   endif

	ptrace(PTRACE_POKEDATA, process.pid, (void *)((mem_uintptr_t)injection_addr), old_data);

	ptrace(PTRACE_SETREGS, process.pid, NULL, &old_regs);
	ptrace(PTRACE_DETACH, process.pid, NULL, NULL);
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	return ret;
}

LIBMEM_EXTERN mem_bool_t         mem_ex_protect(mem_process_t process, mem_voidptr_t src, mem_size_t size, mem_prot_t protection, mem_prot_t *old_protection)
{
	/*
	 * Description:
	 *   Changes the protection flags
	 *   from page of 'src' to 'size' bytes
	 *   after to 'protection' on the
	 *   process 'process'
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;

#	if   MEM_OS == MEM_WIN
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return ret;
	DWORD old_prot = 0;
	ret = VirtualProtectEx(hProcess, src, size, protection, &old_prot) != 0 ? MEM_TRUE : MEM_FALSE;
	if (old_protection) *old_protection = old_prot;
	CloseHandle(hProcess);
#	elif MEM_OS == MEM_LINUX
	if (old_protection)
	{
		mem_page_t page = mem_ex_get_page(process, src);
		*old_protection = page.protection;
	}

	ret = mem_ex_syscall(process, __NR_mprotect, src, (mem_voidptr_t)size, (mem_voidptr_t)(mem_uintptr_t)protection, NULL, NULL, NULL) == 0 ? MEM_TRUE : MEM_FALSE;
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_ex_allocate(mem_process_t process, mem_size_t size, mem_prot_t protection)
{
	/*
	 * Description:
	 *   Allocates 'size' bytes of memory
	 *   with the protection flags 'protection'
	 *   on the process 'process'
	 *
	 * Return Value:
	 *   Returns the address of the allocated
	 *   memory or 'MEM_BAD' on error
	 */

	mem_voidptr_t alloc = (mem_voidptr_t)MEM_BAD;

#	if   MEM_OS == MEM_WIN
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return alloc;
	alloc = (mem_voidptr_t)VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, protection);
	if (!alloc) alloc = (mem_voidptr_t)MEM_BAD;
	CloseHandle(hProcess);
#	elif MEM_OS == MEM_LINUX
	mem_int_t syscall_n = -1;
	switch (process.arch)
	{
	case MEM_ARCH_x86_32:
		/* syscall_n = __NR_mmap2; */
		syscall_n = 192;
		break;
	case MEM_ARCH_x86_64:
		/* syscall_n = __NR_mmap; */
		syscall_n = 9;
		break;
	default:
		return alloc;
	}

	alloc = mem_ex_syscall(process, syscall_n, (mem_voidptr_t)0, (mem_voidptr_t)size, (mem_voidptr_t)(mem_uintptr_t)protection, (mem_voidptr_t)(MAP_PRIVATE | MAP_ANON), (mem_voidptr_t)-1, (mem_voidptr_t)0);
	if (alloc == (mem_voidptr_t)-1 || (mem_uintptr_t)alloc >= (mem_uintptr_t)-4096)
		alloc = (mem_voidptr_t)MEM_BAD;
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	return alloc;
}

LIBMEM_EXTERN mem_bool_t         mem_ex_deallocate(mem_process_t process, mem_voidptr_t src, mem_size_t size)
{
	/*
	 * Description:
	 *   Deallocates 'size' bytes of 'src'
	 *   on the process 'process'
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
#	if   MEM_OS == MEM_WIN
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return ret;
	ret = VirtualFreeEx(hProcess, src, 0, MEM_RELEASE) != 0 ? MEM_TRUE : MEM_FALSE;
	CloseHandle(hProcess);
#	elif MEM_OS == MEM_LINUX
	ret = mem_ex_syscall(process, __NR_munmap, src, (mem_voidptr_t)size, NULL, NULL, NULL, NULL) != (mem_voidptr_t)MAP_FAILED ? MEM_TRUE : MEM_FALSE;
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_ex_scan(mem_process_t process, mem_data_t data, mem_size_t size, mem_voidptr_t start, mem_voidptr_t stop)
{
	/*
	 * Description:
	 *   Searches for 'size' bytes of 'data'
	 *   from 'start' to 'stop' on process
	 *   'process'
	 *
	 * Return Value:
	 *   Returns the first occurrence of 'data'
	 *   between 'start' and 'stop' or 'MEM_BAD'
	 *   if no occurrence was found
	 */

	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD;

	mem_data_t i = (mem_data_t)NULL;
	for (i = (mem_data_t)start; (mem_uintptr_t)&i[size] <= (mem_uintptr_t)stop; i = &i[1])
	{
		mem_int_t found = MEM_TRUE;

		mem_data_t buffer = (mem_data_t)malloc(size);
		if (!buffer) break;

		mem_ex_write(process, buffer, i, size);

		mem_size_t j = (mem_size_t)NULL;
		for (j = 0; j < size; j++)
		{
			found &= buffer[j] == data[j];

			if (!found) break;
		}

		free(buffer);

		if (found)
		{
			ret = (mem_voidptr_t)i;
			break;
		}
	}

	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_ex_pattern_scan(mem_process_t process, mem_data_t pattern, mem_tstring_t mask, mem_voidptr_t start, mem_voidptr_t stop)
{
	/*
	 * Description:
	 *   Searches for 'size' bytes of 'data'
	 *   from 'start' to 'stop' on process
	 *   'process' and checks a byte mask
	 *
	 * Return Value:
	 *   Returns the first occurrence of 'data'
	 *   between 'start' and 'stop' or 'MEM_BAD'
	 *   if no occurrence was found
	 */

	mem_voidptr_t ret = (mem_voidptr_t)MEM_BAD;
	mem_size_t size = MEM_STR_LEN(mask);

	mem_data_t i = (mem_data_t)NULL;
	for (i = (mem_data_t)start; (mem_uintptr_t)&i[size] <= (mem_uintptr_t)stop; i = &i[1])
	{
		mem_int_t found = MEM_TRUE;

		mem_data_t buffer = (mem_data_t)malloc(size);
		if (!buffer) break;

		mem_ex_write(process, buffer, i, size);

		mem_size_t j = (mem_size_t)NULL;
		for (j = 0; j < size; j++)
		{
			found &= ((mask[j] != MEM_STR('x') && mask[j] != MEM_STR('X')) || buffer[j] == pattern[j]);

			if (!found) break;
		}

		free(buffer);

		if (found)
		{
			ret = (mem_voidptr_t)i;
			break;
		}
	}

	return ret;
}

LIBMEM_EXTERN mem_module_t       mem_ex_load_module(mem_process_t process, mem_tstring_t path)
{
	/*
	 * Description:
	 *   Loads the module from
	 *   'path' into the
	 *   process 'process'
	 *
	 * Return Value:
	 *   Returns information about
	 *   the loaded module or a
	 *   'mem_module_t' filled with
	 *   invalid values on error
	 */

	mem_module_t mod = { 0 };

#	if   MEM_OS == MEM_WIN
	mem_size_t path_size = (MEM_STR_LEN(path) + 1) * sizeof(mem_tchar_t);
	mem_voidptr_t path_buffer_ex = mem_ex_allocate(process, path_size, PAGE_EXECUTE_READWRITE);
	if (path_buffer_ex == (mem_voidptr_t)MEM_BAD) return mod;
	mem_ex_set(process, path_buffer_ex, 0x0, path_size);
	mem_ex_write(process, path_buffer_ex, path, path_size);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (hProcess)
	{
		HANDLE hThread = (HANDLE)CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, path_buffer_ex, 0, NULL);
		if (hThread)
		{
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		}

		CloseHandle(hProcess);
	}

	mem_ex_deallocate(process, path_buffer_ex, path_size);

	mod = mem_ex_get_module(process, path);

#	elif MEM_OS == MEM_LINUX

	if (process.arch < 0 || process.arch >= MEM_ARCH_UNKNOWN)
		return mod;

	extern void *__libc_dlopen_mode(const char *filename, int flag);
	Dl_info libc_info = { 0 };
	if (!dladdr((void *)__libc_dlopen_mode, &libc_info)) return mod;

	mem_uintptr_t dlopen_offset = (mem_uintptr_t)libc_info.dli_saddr - (mem_uintptr_t)libc_info.dli_fbase;

	mem_tchar_t path_buffer[64] = { 0 };
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/maps", process.pid);

	int maps_file = open(path_buffer, O_RDONLY);
	if (maps_file == -1) return mod;
	mem_size_t maps_size = 0;
	mem_tstring_t maps_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(maps_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, maps_buffer, maps_size * sizeof(mem_tchar_t));
		free(maps_buffer);
		maps_buffer = holder;
		maps_buffer[maps_size] = c;
		maps_buffer[maps_size + 1] = '\0';
	}
	close(maps_file);
	if (!maps_buffer) return mod;

	mem_tchar_t *p_module_path_ptr = (mem_tchar_t *)NULL;
	mem_tchar_t *p_module_path_endptr = (mem_tchar_t *)NULL;

	if (
		(
			(p_module_path_ptr = MEM_STR_STR(maps_buffer, MEM_STR("/libc-"))) ||
			(p_module_path_ptr = MEM_STR_STR(maps_buffer, MEM_STR("/libc.")))
		) &&
		(p_module_path_endptr = MEM_STR_CHR(p_module_path_ptr, MEM_STR('\n')))
	)
	{
		mem_size_t module_ref_size = (mem_uintptr_t)p_module_path_endptr - (mem_uintptr_t)p_module_path_ptr;
		mem_tstring_t module_ref = (mem_tstring_t)malloc(module_ref_size + sizeof(mem_tchar_t));
		memset(module_ref, 0x0, module_ref_size + sizeof(mem_tchar_t));
		memcpy(module_ref, p_module_path_ptr, module_ref_size);

		mem_module_t libc_ex = mem_ex_get_module(process, module_ref);
		free(module_ref);

		mem_voidptr_t dlopen_ex = (mem_voidptr_t)((mem_uintptr_t)libc_ex.base + dlopen_offset);
		mem_payload_t inj_buf = MEM_PAYLOADS[MEM_ASM_INVALID];
		switch (process.arch)
		{
		case MEM_ARCH_x86_32:
			inj_buf = MEM_PAYLOADS[MEM_ASM_x86_LIBCALL32_2];
			break;
		case MEM_ARCH_x86_64:
			inj_buf = MEM_PAYLOADS[MEM_ASM_x86_LIBCALL64];
			break;
		default:
			break;
		}

		mem_size_t path_size = (MEM_STR_LEN(path) + 1) * sizeof(mem_tchar_t);
		mem_size_t inj_size = inj_buf.size + path_size;
		mem_voidptr_t inj_addr = mem_ex_allocate(process, inj_size, PROT_EXEC | PROT_READ | PROT_WRITE);
		if (inj_addr != (mem_voidptr_t)MEM_BAD)
		{
			mem_voidptr_t path_addr = (mem_voidptr_t)((mem_uintptr_t)inj_addr + inj_buf.size);
			mem_ex_write(process, inj_addr, inj_buf.payload, inj_buf.size);
			mem_ex_write(process, path_addr, path, path_size);

			int status;
			struct user_regs_struct old_regs, regs;
			/* void *handle = (void *)NULL; */

			ptrace(PTRACE_ATTACH, process.pid, NULL, NULL);
			wait(&status);
			ptrace(PTRACE_GETREGS, process.pid, NULL, &old_regs);

			regs = old_regs;

#			if   MEM_ARCH == _MEM_ARCH_x86_32
			regs.eax = (mem_intptr_t)dlopen_ex;
			regs.ebx = (mem_intptr_t)path_addr;
			regs.ecx = (mem_intptr_t)RTLD_LAZY;
			regs.eip = (mem_intptr_t)inj_addr;
#			elif MEM_ARCH == _MEM_ARCH_x86_64
			regs.rax = (mem_intptr_t)dlopen_ex;
			regs.rdi = (mem_intptr_t)path_addr;
			regs.rsi = (mem_intptr_t)RTLD_LAZY;
			regs.rip = (mem_intptr_t)inj_addr;
#			endif

			ptrace(PTRACE_SETREGS, process.pid, NULL, &regs);
			ptrace(PTRACE_CONT, process.pid, NULL, NULL);
			waitpid(process.pid, &status, WSTOPPED);
			ptrace(PTRACE_GETREGS, process.pid, NULL, &regs);

			/*
#			if   MEM_ARCH == _MEM_ARCH_x86_32
			handle = (void *)regs.eax;
#			elif MEM_ARCH == _MEM_ARCH_x86_64
			handle = (void *)regs.rax;
#			endif
			*/

			ptrace(PTRACE_SETREGS, process.pid, NULL, &old_regs);
			ptrace(PTRACE_DETACH, process.pid, NULL, NULL);

			mem_ex_deallocate(process, inj_addr, inj_size);
			mod = mem_ex_get_module(process, path);
		}
	}

	free(maps_buffer);
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	return mod;
}

LIBMEM_EXTERN mem_bool_t         mem_ex_unload_module(mem_process_t process, mem_module_t mod)
{
	/*
	 * Description:
	 *   Unloads the module from
	 *   'path' into the
	 *   process 'process'
	 *
	 * Return Value:
	 *   Returns 'MEM_TRUE' on success
	 *   or 'MEM_FALSE' on error
	 */

	mem_bool_t ret = MEM_FALSE;
#	if   MEM_OS == MEM_WIN
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process.pid);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return ret;

	mem_tstring_t module_ref = (mem_tstring_t)NULL;
	mem_size_t    module_ref_len = 0;
	if ((module_ref_len = mem_ex_get_module_name(process, mod, &module_ref)))
	{
		mem_size_t module_ref_size = (module_ref_len + 1) * sizeof(mem_tchar_t);
		mem_voidptr_t module_ref_ex = mem_ex_allocate(process, module_ref_size, PAGE_READWRITE);
		if (module_ref_ex != (mem_voidptr_t)MEM_BAD)
		{
			if (mem_ex_write(process, module_ref_ex, module_ref, module_ref_size) == MEM_TRUE)
			{
				HANDLE hThread = (HANDLE)CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetModuleHandle, module_ref_ex, 0, NULL);
				if (hThread)
				{
					HMODULE hModuleEx = (HMODULE)INVALID_HANDLE_VALUE;
					WaitForSingleObject(hThread, INFINITE);
					GetExitCodeThread(hThread, (LPDWORD)&hModuleEx);
					CloseHandle(hThread);

					if (hModuleEx && hModuleEx != (HMODULE)INVALID_HANDLE_VALUE)
					{
						hThread = (HANDLE)CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, hModuleEx, 0, NULL);
						if (hThread)
						{
							WaitForSingleObject(hThread, INFINITE);
							CloseHandle(hThread);
							ret = MEM_TRUE;
						}
					}
				}
			}
			mem_ex_deallocate(process, module_ref_ex, module_ref_size);
		}
		free(module_ref);
	}

	CloseHandle(hProcess);
#	elif MEM_OS == MEM_LINUX
	if (process.arch < 0 || process.arch >= MEM_ARCH_UNKNOWN)
		return ret;

	mem_tstring_t path = (mem_tstring_t)NULL;
	mem_size_t path_len = mem_ex_get_module_path(process, mod, &path);
	if (!path_len) return ret;

	extern void *__libc_dlopen_mode(const char *filename, int flag);
	extern int   __libc_dlclose(void *map);
	Dl_info libc_info = { 0 };
	if (!dladdr((void *)__libc_dlopen_mode, &libc_info)) return ret;

	mem_uintptr_t dlopen_offset = (mem_uintptr_t)libc_info.dli_saddr - (mem_uintptr_t)libc_info.dli_fbase;

	if (!dladdr((void *)__libc_dlclose, &libc_info)) return ret;
	mem_uintptr_t dlclose_offset = (mem_uintptr_t)libc_info.dli_saddr - (mem_uintptr_t)libc_info.dli_fbase;

	mem_tchar_t path_buffer[64] = { 0 };
	snprintf(path_buffer, sizeof(path_buffer) - sizeof(mem_tchar_t), "/proc/%i/maps", process.pid);

	int maps_file = open(path_buffer, O_RDONLY);
	if (maps_file == -1) return ret;
	mem_size_t maps_size = 0;
	mem_tstring_t maps_buffer = (mem_tstring_t)malloc(sizeof(mem_tchar_t));
	int read_check = 0;
	mem_tchar_t c = (mem_tchar_t)0;
	for (c = 0; (read_check = read(maps_file, &c, 1)) > 0; maps_size++)
	{
		mem_tchar_t *holder = (mem_tchar_t *)malloc((maps_size + 2) * sizeof(mem_tchar_t));
		memcpy(holder, maps_buffer, maps_size * sizeof(mem_tchar_t));
		free(maps_buffer);
		maps_buffer = holder;
		maps_buffer[maps_size] = c;
		maps_buffer[maps_size + 1] = '\0';
	}
	close(maps_file);
	if (!maps_buffer) return ret;

	mem_tchar_t *p_module_path_ptr = (mem_tchar_t *)NULL;
	mem_tchar_t *p_module_path_endptr = (mem_tchar_t *)NULL;

	if (
		(
			(p_module_path_ptr = MEM_STR_STR(maps_buffer, MEM_STR("/libc-"))) ||
			(p_module_path_ptr = MEM_STR_STR(maps_buffer, MEM_STR("/libc.")))
		) &&
		(p_module_path_endptr = MEM_STR_CHR(p_module_path_ptr, MEM_STR('\n')))
	)
	{
		mem_size_t module_ref_size = (mem_uintptr_t)p_module_path_endptr - (mem_uintptr_t)p_module_path_ptr;
		mem_tstring_t module_ref = (mem_tstring_t)malloc(module_ref_size + sizeof(mem_tchar_t));
		memset(module_ref, 0x0, module_ref_size + sizeof(mem_tchar_t));
		memcpy(module_ref, p_module_path_ptr, module_ref_size);

		mem_module_t libc_ex = mem_ex_get_module(process, module_ref);
		free(module_ref);

		mem_voidptr_t dlopen_ex = (mem_voidptr_t)((mem_uintptr_t)libc_ex.base + dlopen_offset);
		mem_voidptr_t dlclose_ex = (mem_voidptr_t)((mem_uintptr_t)libc_ex.base + dlclose_offset);
		mem_payload_t inj_buf = MEM_PAYLOADS[MEM_ASM_INVALID];
		switch (process.arch)
		{
		case MEM_ARCH_x86_32:
			inj_buf = MEM_PAYLOADS[MEM_ASM_x86_LIBCALL32_2];
			break;
		case MEM_ARCH_x86_64:
			inj_buf = MEM_PAYLOADS[MEM_ASM_x86_LIBCALL64];
			break;
		default:
			break;
		}

		mem_size_t path_size = (path_len + 1) * sizeof(mem_tchar_t);
		mem_size_t inj_size = inj_buf.size + path_size;
		mem_voidptr_t inj_addr = mem_ex_allocate(process, inj_size, PROT_EXEC | PROT_READ | PROT_WRITE);
		if (inj_addr != (mem_voidptr_t)MEM_BAD)
		{
			mem_voidptr_t path_addr = (mem_voidptr_t)((mem_uintptr_t)inj_addr + inj_buf.size);
			mem_ex_write(process, inj_addr, inj_buf.payload, inj_buf.size);
			mem_ex_write(process, path_addr, path, path_size);

			int status;
			struct user_regs_struct old_regs, regs;
			void *handle = (void *)NULL;

			ptrace(PTRACE_ATTACH, process.pid, NULL, NULL);
			wait(&status);
			ptrace(PTRACE_GETREGS, process.pid, NULL, &old_regs);

			regs = old_regs;

#			if   MEM_ARCH == _MEM_ARCH_x86_32
			regs.eax = (mem_intptr_t)dlopen_ex;
			regs.ebx = (mem_intptr_t)path_addr;
			regs.ecx = (mem_intptr_t)RTLD_LAZY;
			regs.eip = (mem_intptr_t)inj_addr;
#			elif MEM_ARCH == _MEM_ARCH_x86_64
			regs.rax = (mem_intptr_t)dlopen_ex;
			regs.rdi = (mem_intptr_t)path_addr;
			regs.rsi = (mem_intptr_t)RTLD_LAZY;
			regs.rip = (mem_intptr_t)inj_addr;
#			endif

			ptrace(PTRACE_SETREGS, process.pid, NULL, &regs);
			ptrace(PTRACE_CONT, process.pid, NULL, NULL);
			waitpid(process.pid, &status, WSTOPPED);
			ptrace(PTRACE_GETREGS, process.pid, NULL, &regs);

#			if   MEM_ARCH == _MEM_ARCH_x86_32
			handle = (void *)regs.eax;
#			elif MEM_ARCH == _MEM_ARCH_x86_64
			handle = (void *)regs.rax;
#			endif

			ptrace(PTRACE_SETREGS, process.pid, NULL, &old_regs);
			ptrace(PTRACE_DETACH, process.pid, NULL, NULL);

			mem_ex_deallocate(process, inj_addr, inj_size);
			if (!handle) return ret;

			switch (process.arch)
			{
			case MEM_ARCH_x86_32:
				inj_buf = MEM_PAYLOADS[MEM_ASM_x86_LIBCALL32_2];
				break;
			case MEM_ARCH_x86_64:
				inj_buf = MEM_PAYLOADS[MEM_ASM_x86_LIBCALL64];
				break;
			default:
				break;
			}

			inj_size = inj_buf.size;

			inj_addr = mem_ex_allocate(process, inj_size, PROT_EXEC | PROT_READ | PROT_WRITE);
			if (inj_addr)
			{
				switch (process.arch)
				{
				case MEM_ARCH_x86_32:
					inj_buf = MEM_PAYLOADS[MEM_ASM_x86_LIBCALL32_1];
					break;
				case MEM_ARCH_x86_64:
					inj_buf = MEM_PAYLOADS[MEM_ASM_x86_LIBCALL64];
					break;
				default:
					break;
				}

				ptrace(PTRACE_ATTACH, process.pid, NULL, NULL);
				wait(&status);
				ptrace(PTRACE_GETREGS, process.pid, NULL, &old_regs);

				regs = old_regs;

#				if   MEM_ARCH == _MEM_ARCH_x86_32
				regs.eax = (mem_intptr_t)dlclose_ex;
				regs.ebx = (mem_intptr_t)handle;
				regs.eip = (mem_intptr_t)inj_addr;
#				elif MEM_ARCH == _MEM_ARCH_x86_64
				regs.rax = (mem_intptr_t)dlclose_ex;
				regs.rdi = (mem_intptr_t)handle;
				regs.rip = (mem_intptr_t)inj_addr;
#				endif

				ptrace(PTRACE_SETREGS, process.pid, NULL, &regs);
				ptrace(PTRACE_CONT, process.pid, NULL, NULL);
				waitpid(process.pid, &status, WSTOPPED);
				ptrace(PTRACE_GETREGS, process.pid, NULL, &regs);

				mem_intptr_t dlclose_ret = 0;
#				if   MEM_ARCH == _MEM_ARCH_x86_32
				dlclose_ret = (mem_intptr_t)regs.eax;
#				elif MEM_ARCH == _MEM_ARCH_x86_64
				dlclose_ret = (mem_intptr_t)regs.rax;
#				endif

				ptrace(PTRACE_SETREGS, process.pid, NULL, &old_regs);
				ptrace(PTRACE_DETACH, process.pid, NULL, NULL);

				mem_ex_deallocate(process, inj_addr, inj_size);
				if (!dlclose_ret) return ret;
			}
		}
	}

	free(maps_buffer);
	free(path);
#	elif MEM_OS == MEM_BSD
	/* WIP */
#	endif

	return ret;
}

LIBMEM_EXTERN mem_voidptr_t      mem_ex_get_symbol(mem_process_t process, mem_module_t mod, mem_cstring_t symbol)
{
	/*
	 * Description:
	 *  Gets the address of the symbol 'symbol'
	 *  of the module 'mod' on the process 'process'
	 *
	 * Return Value:
	 *   Returns the address of the symbol
	 *   or 'MEM_BAD' on error
	 */

	mem_voidptr_t addr = (mem_voidptr_t)MEM_BAD;
#	if   MEM_OS == MEM_WIN
	mem_tstring_t module_ref = (mem_tstring_t)NULL;
	if (!mem_ex_get_module_path(process, mod, &module_ref)) return addr;
	HMODULE hModule = LoadLibraryEx(module_ref, NULL, DONT_RESOLVE_DLL_REFERENCES);
	free(module_ref);
	if (!hModule) return addr;

	MODULEINFO modinfo = { 0 };
	if (!GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(modinfo))) return addr;

	mem_voidptr_t sym_in = (mem_voidptr_t)GetProcAddress(hModule, symbol);
	if (!sym_in) return addr;

	mem_uintptr_t sym_offset = (mem_uintptr_t)sym_in - (mem_uintptr_t)modinfo.lpBaseOfDll;

	addr = (mem_voidptr_t)((mem_uintptr_t)mod.base + sym_offset);

#	elif MEM_OS == MEM_LINUX || MEM_OS == MEM_BSD
	mem_tstring_t module_ref = (mem_tstring_t)NULL;
	if (!mem_ex_get_module_path(process, mod, &module_ref)) return addr;
	mem_module_t mod_in = mem_in_load_module(module_ref);
	free(module_ref);
	mem_voidptr_t sym_in = mem_in_get_symbol(mod_in, symbol);
	if (!sym_in) return addr;
	mem_uintptr_t sym_offset = (mem_uintptr_t)sym_in - (mem_uintptr_t)mod_in.base;
	addr = (mem_voidptr_t)((mem_uintptr_t)mod.base + sym_offset);
#	endif

	return addr;
}

#endif /* MEM_COMPATIBLE */
