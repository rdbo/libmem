/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2023    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <libmem/libmem.h>
#include <windows.h>
#include <winutils/winutils.h>

/* TODO: Verify that this function works with 64 bit process and 32 bit library */
LM_API lm_bool_t LM_CALL
LM_EnumSymbols(const lm_module_t  *module,
	       lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
					     lm_void_t   *arg),
	       lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	BOOL is_loaded = FALSE;
	HMODULE hmod;
	lm_address_t modbase;
	PIMAGE_DOS_HEADER pdoshdr;
	PIMAGE_NT_HEADERS pnthdr;
	PIMAGE_EXPORT_DIRECTORY pexportdir;
	DWORD *export_names;
	DWORD *export_funcs;
	DWORD i;
	lm_symbol_t symbol;

	/* Attempt to get the module handle without loading the library */
	hmod = GetModuleHandle(module->path);
	if (!hmod) {
		WCHAR *wpath;

		wpath = wcstoutf8(module->path, NULL, 0);
		if (!wpath)
			return result;

		/* Load library purely for getting resources, and not executing */
		hmod = LoadLibraryExW(module->path, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
		free(wpath);

		if (!hmod)
			return result;

		is_loaded = TRUE;
	}

	/*
	 * From: https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo
	 *
	 * "The load address of a module is the same as the HMODULE value."
	 */
	modbase = (lm_address_t)hmod;

	pdoshdr = (PIMAGE_DOS_HEADER)modbase;
	printf("DOS HEADER: %p\n", (void *)pdoshdr);
	pnthdr = (PIMAGE_NT_HEADERS)(modbase + (lm_address_t)pdoshdr->e_lfanew);
	printf("NT HEADER: %p\n", (void *)pnthdr);
	pexportdir = (PIMAGE_EXPORT_DIRECTORY)(
		modbase + pnthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	);
	printf("Export Dir: %p\n", (void *)pexportdir);
	export_names = (DWORD *)(modbase + pexportdir->AddressOfNames);
	printf("EXPORT NAMES: %p\n", export_names);
	export_funcs = (DWORD *)(modbase + pexportdir->AddressOfFunctions);
	printf("EXPORT FUNCS: %p\n", export_funcs);
	printf("NUMBER OF FUNCS: %d\n", (int)pexportdir->NumberOfFunctions);

	for (i = 0; i < pexportdir->NumberOfNames && i < pexportdir->NumberOfFunctions; ++i) {
		symbol.name = (lm_string_t)(modbase + export_names[i]);
		printf("symbol name: %s\n", symbol.name);

		symbol.address = (lm_address_t)(module->base + export_funcs[i]);
		printf("symbol address: %p\n", (void *)symbol.address);

		if (callback(&symbol, arg) == LM_FALSE)
			break;
	}
	
	result = LM_TRUE;
CLOSE_EXIT:
	if (is_loaded)
		CloseHandle(hmod);
	return result;
}
