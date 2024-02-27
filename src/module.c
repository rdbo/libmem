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

#include "internal.h"

LM_API lm_bool_t LM_CALL
LM_EnumModules(lm_bool_t (LM_CALL *callback)(lm_module_t *pmod,
					     lm_void_t   *arg),
	       lm_void_t          *arg)
{
	lm_process_t proc;

	if (!callback)
		return LM_FALSE;

	if (!LM_GetProcess(&proc))
		return LM_FALSE;

	/* TODO: Add manual implementation for *nix, using `dl_iterate_phdr` or through `link_map`s chain */
	return LM_EnumModulesEx(&proc, callback, arg);
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *pproc,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *pmod,
					       lm_void_t   *arg),
		 lm_void_t          *arg)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || !callback)
		return LM_FALSE;

	return _LM_EnumModulesEx(pproc, callback, arg);
}

/********************************/

typedef struct {
	lm_module_t *modbuf;
	lm_string_t  name;
	lm_size_t    len;
} _lm_find_mod_t;

LM_PRIVATE lm_bool_t LM_CALL
_LM_FindModuleCallback(lm_module_t *pmod,
		       lm_void_t   *arg)
{
	_lm_find_mod_t *parg = (_lm_find_mod_t *)arg;
	lm_size_t       pathlen;

	pathlen = LM_STRLEN(pmod->path);

	if (pathlen >= parg->len) {
		if (!LM_STRCMP(&(pmod->path)[pathlen - parg->len], parg->name)) {
			*(parg->modbuf) = *pmod;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_FindModule(lm_string_t  name,
	      lm_module_t *modbuf)
{
	_lm_find_mod_t arg;

	if (!name || !modbuf)
		return LM_FALSE;

	arg.modbuf = modbuf;
	arg.modbuf->size = 0;
	arg.name = name;
	arg.len = LM_STRLEN(arg.name);

	if (!LM_EnumModules(_LM_FindModuleCallback, (lm_void_t *)&arg))
		return LM_FALSE;

	return arg.modbuf->size > 0 ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_FindModuleEx(const lm_process_t *pproc,
		lm_string_t         name,
		lm_module_t        *modbuf)
{
	_lm_find_mod_t arg;

	if (!pproc || !LM_VALID_PROCESS(pproc) || !name || !modbuf)
		return LM_FALSE;

	arg.modbuf = modbuf;
	arg.modbuf->size = 0;
	arg.name = name;
	arg.len = LM_STRLEN(arg.name);

	if (!LM_EnumModulesEx(pproc, _LM_FindModuleCallback, (lm_void_t *)&arg))
		return LM_FALSE;

	return arg.modbuf->size > 0 ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_LoadModule(lm_string_t  path,
	      lm_module_t *modbuf)
{
	/* modbuf can be NULL. in that case, the module info won't be saved */
	if (!path)
		return LM_FALSE;

	if (!_LM_LoadModule(path))
		return LM_FALSE;

	/* TODO (?): Unload the module if it doesn't find it - or
	             retrieve the module directly in the OS-specific functions */
	if (modbuf && !LM_FindModule(path, modbuf))
		return LM_FALSE;

	return LM_TRUE;
}

/********************************/

/* TODO: implement FreeBSD support on injector module */
#if LM_OS == LM_OS_BSD
LM_PRIVATE lm_bool_t
_LM_LoadModuleEx(const lm_process_t *pproc,
		 lm_string_t         path,
		 lm_module_t        *modbuf)
{
	if (!_LM_CallDlopen(pproc, path, RTLD_LAZY, LM_NULLPTR))
		return LM_FALSE;

	if (modbuf && !LM_FindModuleEx(pproc, path, modbuf))
		return LM_FALSE;

	return LM_TRUE;
}
#else
#include <injector.h>

LM_PRIVATE lm_bool_t
_LM_LoadModuleEx(const lm_process_t *pproc,
		 lm_string_t         path,
		 lm_module_t        *modbuf)
{
	injector_t *injector;

	if (injector_attach(&injector, pproc->pid))
		return LM_FALSE;
	
        if (injector_inject(injector, path, NULL))
		return LM_FALSE;

        injector_detach(injector);

	if (modbuf && !LM_FindModuleEx(pproc, path, modbuf))
		return LM_FALSE;

	return LM_TRUE;
}
#endif

LM_API lm_bool_t LM_CALL
LM_LoadModuleEx(const lm_process_t *pproc,
		lm_string_t         path,
		lm_module_t        *modbuf)
{
	if (!pproc || !LM_VALID_PROCESS(pproc) || !path)
		return LM_FALSE;

	return _LM_LoadModuleEx(pproc, path, modbuf);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_UnloadModule(lm_module_t *pmod)
{
	HMODULE hModule;

	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
			  (LPTSTR)pmod->base, &hModule);

	if (!hModule)
		return LM_FALSE;

	FreeLibrary(hModule);
	return LM_TRUE;
}
#elif LM_OS == LM_OS_BSD
LM_PRIVATE lm_bool_t
_LM_UnloadModule(lm_module_t *pmod)
{
	void *handle;

	/* Retrieve handle by calling 'dlopen' again, but without loading the module */
	handle = dlopen(pmod->path, RTLD_NOLOAD);
	if (!handle)
		return LM_FALSE;

	dlclose(handle); /* Decrease reference count */
	dlclose(handle); /* Unload module */

	return LM_TRUE;
}
#else
LM_PRIVATE lm_bool_t
_LM_UnloadModule(lm_module_t *pmod)
{
	/* NOTE: 'dlclose' is not required to unload any modules, but this is as good as it gets */
	struct link_map *base_link;
	struct link_map *handle;
	lm_bool_t has_unloaded = LM_FALSE;

	/* Retrieve 'link_map' of the executable to access the 'link_map' chain */
	base_link = (struct link_map *)dlopen(NULL, RTLD_NOLOAD);
	if (!base_link)
		return LM_FALSE;

	/* Loop through 'link_map' chain */
	for (handle = base_link; handle; handle = handle->l_next) {
		if ((lm_address_t)handle->l_addr == pmod->base) {
			dlclose(handle);
			has_unloaded = LM_TRUE;
			break; /* NOTE: Maybe don't break, because there might be other 'link_map's related to this module */
		}

		/* NOTE: Perhaps manually patch 'link_map' chain and deallocate library */
	}

	dlclose(base_link);

	return has_unloaded;
}
#endif

LM_API lm_bool_t LM_CALL
LM_UnloadModule(lm_module_t *pmod)
{
	if (!pmod || !LM_VALID_MODULE(pmod))
		return LM_FALSE;

	return _LM_UnloadModule(pmod);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_UnloadModuleEx(const lm_process_t *pproc,
		   lm_module_t        *pmod)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	MODULEENTRY32 entry;
	HMODULE hModule = NULL;
	HANDLE hProcess;
	HANDLE hThread;

	hSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		pproc->pid
	);

	if (hSnap == INVALID_HANDLE_VALUE)
		return ret;

	entry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &entry)) {
		do {			
			if ((lm_address_t)entry.modBaseAddr == pmod->base) {
				hModule = entry.hModule;
				break;
			}
		} while (Module32Next(hSnap, &entry));
	}

	CloseHandle(hSnap);

	if (!hModule)
		return ret;

	if (!_LM_OpenProc(pproc->pid, &hProcess))
		return ret;

	hThread = (HANDLE)CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, hModule, 0, NULL);

	_LM_CloseProc(&hProcess);

	if (!hThread)
		return ret;

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	ret = LM_TRUE;

	return ret;
}
#else
LM_PRIVATE lm_bool_t
_LM_UnloadModuleEx(const lm_process_t *pproc,
		   lm_module_t        *pmod)
{
	lm_bool_t ret = LM_FALSE;
	void *modhandle;

	if (!_LM_CallDlopen(pproc, pmod->path, RTLD_NOLOAD, &modhandle))
		return ret;

	if (_LM_CallDlclose(pproc, modhandle) && _LM_CallDlclose(pproc, modhandle))
		ret = LM_TRUE;

	return ret;
}
#endif

LM_API lm_bool_t LM_CALL
LM_UnloadModuleEx(const lm_process_t *pproc,
		  lm_module_t        *pmod)
{
	LM_ASSERT(pproc != LM_NULLPTR &&
		  LM_VALID_PROCESS(pproc) &&
		  pmod != LM_NULLPTR &&
		  LM_VALID_MODULE(pmod));

	return _LM_UnloadModuleEx(pproc, pmod);
}

