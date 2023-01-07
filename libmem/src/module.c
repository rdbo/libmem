/*
 *  ----------------------------------
 * |         libmem - by rdbo         |
 * |      Memory Hacking Library      |
 *  ----------------------------------
 */

/*
 * Copyright (C) 2022    Rdbo
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
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

LM_PRIVATE lm_size_t
_LM_GetNameFromPath(lm_char_t *path,
		    lm_char_t *namebuf,
		    lm_size_t  maxlen)
{
	lm_char_t *name;
	lm_size_t   len = 0;

	name = LM_STRRCHR(path, LM_PATH_SEP);
	if (!name) {
		namebuf[0] = LM_STR('\x00');
		return len;
	}

	name = &name[1]; /* skip path separator */

	len = LM_STRLEN(name);
	if (len >= maxlen)
		len = maxlen - 1;

	LM_STRNCPY(namebuf, name, len);
	namebuf[len] = LM_STR('\x00');
	
	return len;
}

/********************************/

LM_API lm_bool_t
LM_EnumModules(lm_bool_t(*callback)(lm_module_t *pmod,
				    lm_void_t   *arg),
	       lm_void_t *arg)
{
	lm_process_t proc;

	LM_ASSERT(callback != LM_NULLPTR);

	if (!LM_GetProcess(&proc))
		return LM_FALSE;

	return LM_EnumModulesEx(&proc, callback, arg);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_EnumModulesEx(lm_process_t *pproc,
		  lm_bool_t   (*callback)(lm_module_t *pmod,
					  lm_void_t   *arg),
		  lm_void_t    *arg)
{
	lm_bool_t ret = LM_FALSE;
	HANDLE hSnap;
	MODULEENTRY32 entry;
	lm_module_t mod;
	lm_size_t path_len;

	hSnap = CreateToolhelp32Snapshot(
		TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
		pproc->pid
	);

	if (hSnap == INVALID_HANDLE_VALUE)
		return ret;

	entry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnap, &entry)) {
		do {
			mod.base = (lm_address_t)entry.modBaseAddr;
			mod.size = (lm_size_t)entry.modBaseSize;
			mod.end  = (lm_address_t)LM_OFFSET(mod.base, mod.size);
			path_len = LM_STRLEN(entry.szExePath);
			if (path_len >= LM_ARRLEN(mod.path))
				path_len = LM_ARRLEN(mod.path) - 1;

			LM_STRNCPY(mod.path, entry.szExePath, path_len);
			mod.path[path_len] = LM_STR('\x00');
			_LM_GetNameFromPath(mod.path, mod.name, LM_ARRLEN(mod.name));

			if (callback(&mod, arg) == LM_FALSE)
				break;
		} while (Module32Next(hSnap, &entry));

		ret = LM_TRUE;
	}

	CloseHandle(hSnap);

	return ret;
}
#else
LM_PRIVATE lm_bool_t
_LM_EnumModulesEx(lm_process_t *pproc,
		  lm_bool_t   (*callback)(lm_module_t *pmod,
					  lm_void_t   *arg),
		  lm_void_t    *arg)
{
	lm_bool_t    ret = LM_FALSE;
	lm_char_t    maps_path[LM_PATH_MAX];
	FILE        *maps_file;
	lm_char_t   *maps_line = NULL;
	lm_size_t    maps_line_len;
	ssize_t      line_len;
	regex_t      regex;
	regmatch_t   matches[5];
	lm_module_t  mod;
	lm_string_t  curpath;

	mod.size = 0;
	mod.path[0] = LM_STR('\x00');

#	if LM_OS == LM_OS_BSD
	if (regcomp(&regex, "^0x([a-z0-9]+)[[:blank:]]+0x([a-z0-9]+)[[:blank:]]+[^/]+(/.*)([[:blank:]])+[A-Z]+[[:blank:]]+.*$", REG_EXTENDED))
		return ret;

	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/map"), LM_PROCFS, pproc->pid);
#	else
	if (regcomp(&regex, "^([a-z0-9]+)-([a-z0-9]+)[^/]+(/.+)$", REG_EXTENDED))
		return ret;

	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/maps"), LM_PROCFS, pproc->pid);
#	endif

	maps_file = LM_FOPEN(maps_path, "r");
	if (!maps_file)
		goto FREE_EXIT;

	while ((line_len = LM_GETLINE(&maps_line, &maps_line_len, maps_file)) > 0) {
		if (regexec(&regex, maps_line, LM_ARRLEN(matches), matches, 0))
			continue;

		maps_line[--line_len] = LM_STR('\x00'); /* remove \n */
#		if LM_OS == LM_OS_BSD
		maps_line[matches[4].rm_so] = LM_STR('\x00');
#		endif
		curpath = &maps_line[matches[3].rm_so];


		/* TODO: Group copies of base and path of first and new module conditions */

		/* if it is the first module, copy the base and path */
		if (LM_STRLEN(mod.path) == 0) {
			lm_size_t pathlen = LM_STRLEN(curpath);

			if (pathlen >= LM_ARRLEN(mod.path))
				pathlen = LM_ARRLEN(mod.path) - 1;

			LM_STRNCPY(mod.path, curpath, pathlen);
			mod.path[pathlen] = LM_STR('\x00');

			_LM_GetNameFromPath(mod.path, mod.name, LM_ARRLEN(mod.name));

			mod.base = (lm_address_t)LM_STRTOP(
				&maps_line[matches[1].rm_so], NULL, 16
			);
		}

		/* if the module changes, run a callback and copy the new base and path */
		if (LM_STRCMP(curpath, mod.path)) {
			lm_size_t pathlen;

			mod.size = (lm_size_t)(
				(lm_uintptr_t)mod.end - (lm_uintptr_t)mod.base
			);

			if (callback(&mod, arg) == LM_FALSE) {
				mod.size = 0; /* prevent last module callback */
				break;
			}

			pathlen = LM_STRLEN(curpath);
			if (pathlen >= LM_ARRLEN(mod.path))
				pathlen = LM_ARRLEN(mod.path) - 1;

			LM_STRNCPY(mod.path, curpath, pathlen);
			mod.path[pathlen] = LM_STR('\x00');

			_LM_GetNameFromPath(mod.path, mod.name, LM_ARRLEN(mod.name));

			mod.base = (lm_address_t)LM_STRTOP(
				&maps_line[matches[1].rm_so], NULL, 16
			);
		}

		/* the module end address should always update, since it's supposed
		   to be the last valid address for a module */
		mod.end = (lm_address_t)LM_STRTOP(
			&maps_line[matches[2].rm_so], NULL, 16
		);
	}

	/* run a callback for the last module */
	if (mod.size != 0)
		callback(&mod, arg);

	ret = LM_TRUE;

	LM_FCLOSE(maps_file);
FREE_EXIT:
	regfree(&regex);
	return ret;
}
#endif

LM_API lm_bool_t
LM_EnumModulesEx(lm_process_t *pproc,
		 lm_bool_t   (*callback)(lm_module_t *pmod,
					 lm_void_t   *arg),
		 lm_void_t    *arg)
{
	LM_ASSERT(pproc != LM_NULLPTR && callback != LM_NULLPTR);

	return _LM_EnumModulesEx(pproc, callback, arg);
}

/********************************/

typedef struct {
	lm_module_t *modbuf;
	lm_string_t  name;
	lm_size_t    len;
} _lm_find_mod_t;

LM_PRIVATE lm_bool_t
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

LM_API lm_bool_t
LM_FindModule(lm_string_t  name,
	      lm_module_t *modbuf)
{
	_lm_find_mod_t arg;

	LM_ASSERT(name != LM_NULLPTR && modbuf != LM_NULLPTR);

	arg.modbuf = modbuf;
	arg.modbuf->size = 0;
	arg.name = name;
	arg.len = LM_STRLEN(arg.name);

	if (!LM_EnumModules(_LM_FindModuleCallback, (lm_void_t *)&arg))
		return LM_FALSE;

	return arg.modbuf->size > 0 ? LM_TRUE : LM_FALSE;
}

/********************************/

LM_API lm_bool_t
LM_FindModuleEx(lm_process_t *pproc,
		lm_string_t   name,
		lm_module_t  *modbuf)
{
	_lm_find_mod_t arg;

	LM_ASSERT(pproc != LM_NULLPTR &&
		  name != LM_NULLPTR &&
		  modbuf != LM_NULLPTR);

	arg.modbuf = modbuf;
	arg.modbuf->size = 0;
	arg.name = name;
	arg.len = LM_STRLEN(arg.name);

	if (!LM_EnumModulesEx(pproc, _LM_FindModuleCallback, (lm_void_t *)&arg))
		return LM_FALSE;

	return arg.modbuf->size > 0 ? LM_TRUE : LM_FALSE;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_LoadModule(lm_string_t path)
{
	return LoadLibrary(path) ? LM_TRUE : LM_FALSE;
}
#else
LM_PRIVATE lm_bool_t
_LM_LoadModule(lm_string_t path)
{
	return dlopen(path, RTLD_LAZY) ? LM_TRUE : LM_FALSE;
}
#endif

LM_API lm_bool_t
LM_LoadModule(lm_string_t  path,
	      lm_module_t *modbuf)
{
	/* modbuf can be NULL. in that case, the module info won't be saved */
	LM_ASSERT(path != LM_NULLPTR);

	if (!_LM_LoadModule(path))
		return LM_FALSE;

	/* TODO (?): Unload the module if it doesn't find it */
	if (modbuf && !LM_FindModule(path, modbuf))
		return LM_FALSE;

	return LM_TRUE;
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_LoadModuleEx(lm_process_t *pproc,
		 lm_string_t   path,
		 lm_module_t  *modbuf)
{
	lm_bool_t    ret = LM_FALSE;
	lm_size_t    modpath_size;
	lm_address_t modpath_addr;
	HANDLE       hProcess;
	HANDLE       hThread;

	modpath_size = (LM_STRLEN(path) + 1) * sizeof(lm_char_t)
	modpath_addr = LM_AllocMemoryEx(pproc, modpath_size, LM_PROT_XRW);
	if (modpath_addr == LM_ADDRESS_BAD)
		return ret;

	if (!LM_WriteMemoryEx(pproc, modpath_addr, path, modpath_size))
		goto FREE_EXIT;

	if (!_LM_OpenProc(pproc->pid, &hProcess))
		goto FREE_EXIT;

	hThread = (HANDLE)CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, modpath_addr, 0, NULL);

	_LM_CloseProc(&hProcess);

	if (!hThread)
		goto FREE_RET;

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	ret = LM_TRUE;
FREE_EXIT:
	LM_FreeMemoryEx(pproc, modpath_addr, modpath_size);
	return ret;
}
#else
LM_PRIVATE lm_bool_t
_LM_LoadModuleEx(lm_process_t *pproc,
		 lm_string_t   path,
		 lm_module_t  *modbuf)
{
	if (!_LM_CallDlopen(pproc, path, RTLD_LAZY, LM_NULLPTR))
		return LM_FALSE;

	if (modbuf && !LM_FindModuleEx(pproc, path, modbuf))
		return LM_FALSE;

	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_LoadModuleEx(lm_process_t *pproc,
		lm_string_t   path,
		lm_module_t  *modbuf)
{
	LM_ASSERT(pproc != LM_NULLPTR && path != LM_NULLPTR);
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
		return LM_FALSE:

	FreeLibrary(hModule);
	return LM_TRUE;
}
#else
LM_PRIVATE lm_bool_t
_LM_UnloadModule(lm_module_t *pmod)
{
	void *libhandle;

	/* reopen the library without loading, which gives us the
	   handle that we can use to decrease the reference count
	   and unload the library */
	libhandle = dlopen(pmod->path, RTLD_NOLOAD);

	if (!libhandle)
		return LM_FALSE;

	dlclose(libhandle);
	dlclose(libhandle);

	return LM_TRUE;
}
#endif

LM_API lm_bool_t
LM_UnloadModule(lm_module_t *pmod)
{
	LM_ASSERT(pmod != LM_NULLPTR);

	return _LM_UnloadModule(pmod);
}

/********************************/

#if LM_OS == LM_OS_WIN
LM_PRIVATE lm_bool_t
_LM_UnloadModuleEx(lm_process_t *pproc,
		   lm_module_t  *pmod)
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
_LM_UnloadModuleEx(lm_process_t *pproc,
		   lm_module_t *pmod)
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

LM_API lm_bool_t
LM_UnloadModuleEx(lm_process_t *pproc,
		  lm_module_t  *pmod)
{
	LM_ASSERT(pproc != LM_NULLPTR && pmod != LM_NULLPTR);

	return _LM_UnloadModuleEx(pproc, pmod);
}

