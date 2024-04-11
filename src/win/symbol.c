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
#include <stdio.h>

/* TODO: Verify that this function works with 64 bit process and 32 bit library */
LM_API lm_bool_t LM_CALL
LM_EnumSymbols(const lm_module_t  *module,
	       lm_bool_t (LM_CALL *callback)(lm_symbol_t *symbol,
					     lm_void_t   *arg),
	       lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	WCHAR wpath[LM_PATH_MAX];
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

	printf("ENUM SYMBOLS CALLED\n");
	fflush(stdout);

	if (!module || !callback)
		return result;

	printf("ARGUMENTS CHECKED\n");
	fflush(stdout);

	if (!utf8towcs(module->path, wpath, LM_PATH_MAX))
		return result;

	printf("UTF8 CONVERTED TO WCS\n");
	fflush(stdout);

	/* Attempt to get the module handle without loading the library */
	hmod = GetModuleHandleW(wpath);
	printf("ATTEMPTED TO GET HMODULE: %p\n", (void *)hmod);
	fflush(stdout);
	if (!hmod) {
		printf("HMODULE NOT FOUND, ATTEMPING TO LOAD LIBRARY\n");
		fflush(stdout);
		/* Load library purely for getting resources, and not executing */
		hmod = LoadLibraryExW(wpath, NULL, DONT_RESOLVE_DLL_REFERENCES);
		printf("LIBRARY LOADED: %p\n", (void *)hmod);
		fflush(stdout);
		if (!hmod)
			return result;

		is_loaded = TRUE;
	}
	printf("STARTED SYMBOL ENUMERATION\n");
	fflush(stdout);

	/*
	 * From: https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-moduleinfo
	 *
	 * "The load address of a module is the same as the HMODULE value."
	 */
	modbase = (lm_address_t)hmod;
	printf("MODBASE: %p\n", (void *)modbase);
	fflush(stdout);

	pdoshdr = (PIMAGE_DOS_HEADER)modbase;
	pnthdr = (PIMAGE_NT_HEADERS)(modbase + (lm_address_t)pdoshdr->e_lfanew);
	printf("NTHDR: %p\n", (void *)pnthdr);
	fflush(stdout);

	pexportdir = (PIMAGE_EXPORT_DIRECTORY)(
		modbase + pnthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	);
	printf("EXPORT DIR: %p\n", (void *)pexportdir);
	fflush(stdout);

	export_names = (DWORD *)(modbase + pexportdir->AddressOfNames);
	printf("EXPORT_NAMES: %p\n", (void *)export_names);
	fflush(stdout);

	export_funcs = (DWORD *)(modbase + pexportdir->AddressOfFunctions);
	printf("EXPORT_FUNCS: %p\n", export_funcs);
	fflush(stdout);

	for (i = 0; i < pexportdir->NumberOfNames && i < pexportdir->NumberOfFunctions; ++i) {
		symbol.name = (lm_string_t)(modbase + export_names[i]);
		printf("SYMBOL NAME: %s\n", symbol.name);
		fflush(stdout);

		symbol.address = (lm_address_t)(module->base + export_funcs[i]);
		printf("SYMBOL ADDRESS: %p\n", symbol.address);
		fflush(stdout);

		if (callback(&symbol, arg) == LM_FALSE)
			break;
	}
	
	result = LM_TRUE;
CLOSE_EXIT:
	if (is_loaded)
		CloseHandle(hmod);
	return result;
}
