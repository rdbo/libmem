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
#include <tlhelp32.h>
#include <psapi.h>

LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					       lm_void_t   *arg),
		 lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	HANDLE hsnap;
	MODULEENTRY32W entry;
	lm_module_t module;

	if (!process || !callback)
		return result;
	
	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process->pid);
	if (hsnap == INVALID_HANDLE_VALUE)
		return result;

	entry.dwSize = sizeof(entry);
	if (!Module32FirstW(hsnap, &entry))
		goto CLEAN_EXIT;

	do {
		if (!wcstoutf8(entry.szExePath, module.path, sizeof(module.path)))
			continue;

		if (!wcstoutf8(entry.szModule, module.name, sizeof(module.name)))
			continue;

		module.base = (lm_address_t)entry.modBaseAddr;
		module.size = (lm_address_t)entry.modBaseSize;
		module.end = module.base + module.size;
		
		if (callback(&module, arg) == LM_FALSE)
			break;
	} while (Module32NextW(hsnap, &entry));

	result = LM_TRUE;

CLEAN_EXIT:
	CloseHandle(hsnap);
	return result;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_LoadModule(lm_string_t  path,
	      lm_module_t *module_out)
{
	WCHAR wpath[LM_PATH_MAX];

	if (!path)
		return LM_FALSE;

	if (!utf8towcs(path, wpath, LM_ARRLEN(wpath)))
		return LM_FALSE;
	
	if (!LoadLibraryW(wpath))
		return LM_FALSE;

	/* TODO: Get library information through the HMODULE returned by LoadLibraryW (should be faster) */

	if (module_out)
		return LM_FindModule(path, module_out);

	return LM_TRUE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_LoadModuleEx(const lm_process_t *process,
		lm_string_t         path,
		lm_module_t        *module_out)
{
	lm_bool_t result = LM_FALSE;
	WCHAR wpath[LM_PATH_MAX];
	lm_address_t modpath_addr;
	HANDLE hproc;
	HANDLE hthread;

	if (!process || !path)
		return result;

	if (!utf8towcs(path, wpath, LM_ARRLEN(wpath)))
		return result;

	modpath_addr = LM_AllocMemoryEx(process, sizeof(wpath), LM_PROT_RW);
	if (modpath_addr == LM_ADDRESS_BAD)
		return result;

	if (!LM_WriteMemoryEx(process, modpath_addr, wpath, sizeof(wpath)))
		goto FREE_EXIT;

	hproc = open_process(process.pid, PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ);
	if (!hproc)
		goto FREE_EXIT;

	hthread = (HANDLE)CreateRemoteThread(hproc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, modpath_addr, 0, NULL);

	close_handle(&hproc);

	if (!hthread)
		goto FREE_EXIT;

	WaitForSingleObject(hthread, INFINITE);
	CloseHandle(hthread);

	result = LM_TRUE;
FREE_EXIT:
	LM_FreeMemoryEx(process, modpath_addr, sizeof(wpath));
	return result;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module)
{
	HMODULE hmod;
	WCHAR wpath[LM_PATH_MAX];

	if (!module)
		return LM_FALSE;

	if (!utf8towcs(module->path, wpath, LM_ARRLEN(wpath)))
		return LM_FALSE;

	hmod = GetModuleHandleW(wpath); /* Increases the reference count by 1 */
	if (!hmod)
		return LM_FALSE;

	/* Decrease the reference count by 2 */
	/* NOTE: This does not ensure that the module was actually unloaded */
	CloseHandle(hmod);
	CloseHandle(hmod);

	return LM_TRUE;
}
