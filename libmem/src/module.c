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

LM_API lm_bool_t
LM_EnumModules(lm_bool_t(*callback)(lm_module_t *pmod,
				    lm_void_t   *arg),
	       lm_void_t *arg)
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
#elif LM_OS == LM_OS_LINUX
LM_PRIVATE lm_bool_t
_LM_EnumModulesEx(lm_process_t *pproc,
		  lm_bool_t   (*callback)(lm_module_t *pmod,
					  lm_void_t   *arg),
		  lm_void_t    *arg)
{
	DIR *d;
	struct dirent *dir;
	regex_t regex;
	regmatch_t matches[3];
	lm_module_t mod;

	lm_address_t start;
	lm_address_t end;
	char path[LM_PATH_MAX];
	char real_path[LM_PATH_MAX];
	ssize_t result;
	lm_char_t *name;
	lm_char_t *tmp;

	LM_CSNPRINTF(path, sizeof(path), "/proc/%d/map_files", pproc->pid);
	d = opendir(path);
	if (!d)
		return LM_FALSE;

	if (regcomp(&regex, "([a-z0-9]+)-([a-z0-9]+)", REG_ICASE | REG_EXTENDED))
		goto CLOSE_RET;

	mod.base = 0;
	mod.end = 0;
	
	while ((dir = readdir(d)) != NULL) {
		if (!regexec(&regex, dir->d_name, 3, matches, 0)) {
			start = (lm_address_t)LM_STRTOP(&dir->d_name[matches[1].rm_so], NULL, 16);
			end = (lm_address_t)LM_STRTOP(&dir->d_name[matches[2].rm_so], NULL, 16);

			LM_SNPRINTF(path, sizeof(path), LM_STR("/proc/%d/map_files/%s"), pproc->pid, dir->d_name);
			if ((result = readlink(path, real_path, sizeof(real_path))) == -1)
				continue;

			real_path[result] = '\0';
			result++;

			if (!mod.base) {
				mod.base = start;
				mod.end = end;
				LM_MEMCPY(mod.path, real_path, (lm_size_t)result); /* TODO: Avoid repetition of this code below */
			} else {
				if (start != mod.end || LM_STRCMP(mod.path, real_path)) {
					LM_MEMCPY(path, mod.path, sizeof(path)); /* temporary path for adding the /proc/<pid>/root prefix later */
					LM_SNPRINTF(mod.path, LM_ARRLEN(mod.path), "/proc/%d/root%s", pproc->pid, path);
					for (tmp = mod.path; (tmp = LM_STRCHR(tmp, LM_STR('/'))) != NULL; tmp = &tmp[1])
						name = tmp;
					name = &name[1];
					LM_STRCPY(mod.name, name);
					mod.size = mod.end - mod.base;

					callback(&mod, arg);
					mod.base = start;
					mod.end = end;
					LM_MEMCPY(mod.path, real_path, (lm_size_t)result);
				} else {
					mod.end = end;
				}
			}
		}
	}

	/* TODO: avoid the repeating code to setup 'mod' */
	if (mod.base) {
		LM_SNPRINTF(mod.path, LM_ARRLEN(mod.path), "/proc/%d/root%s", pproc->pid, real_path); /* Since this is the last module, we don't have to create a copy of 'mod.path', as 'real_path' still holds it */
		for (tmp = mod.path; (tmp = LM_STRCHR(tmp, LM_STR('/'))) != NULL; tmp = &tmp[1])
			name = tmp;
		name = &name[1];
		LM_STRCPY(mod.name, name);
		mod.size = mod.end - mod.base;

		callback(&mod, arg);
	}

	regfree(&regex);

CLOSE_RET:
	closedir(d);
	
	return LM_TRUE;
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

	if (regcomp(&regex, "^0x([a-z0-9]+)[[:blank:]]+0x([a-z0-9]+)[[:blank:]]+[^/]+(/.*)([[:blank:]])+[A-Z]+[[:blank:]]+.*$", REG_EXTENDED))
		return ret;

	LM_SNPRINTF(maps_path, LM_ARRLEN(maps_path),
		    LM_STR("%s/%d/map"), LM_PROCFS, pproc->pid);

	maps_file = LM_FOPEN(maps_path, "r");
	if (!maps_file)
		goto FREE_EXIT;

	while ((line_len = LM_GETLINE(&maps_line, &maps_line_len, maps_file)) > 0) {
		if (regexec(&regex, maps_line, LM_ARRLEN(matches), matches, 0))
			continue;

		maps_line[--line_len] = LM_STR('\x00'); /* remove \n */
		maps_line[matches[4].rm_so] = LM_STR('\x00');
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

			/* NOTE: This is a fix for virtualized filesystems on Linux.
			 * The "magic symlink" directory `/proc/<PID>/root` gives a
			 * root filesystem viewed from the process' perspective, unlike
			 * `/proc/<PID>/maps`, which only gives information about
			 * what the process thinks the paths are. This is useful for
			 * getting modules for apps that are "virtualized", like Flatpaks
			 * and others.
			 * TODO: Test this on BSD.
			 */
			/*
#			if LM_OS == LM_OS_LINUX
			{
				lm_char_t old_path[LM_PATH_MAX];

				LM_STRNCPY(old_path, mod.path, LM_PATH_MAX);
				LM_SNPRINTF(mod.path, LM_ARRLEN(mod.path), LM_STR("/proc/%d/root%s"), pproc->pid, old_path);
			}
#			endif
			*/

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
	if (mod.size != 0) {
		/* NOTE: This is a fix for virtualized filesystems on Linux.
		 * The "magic symlink" directory `/proc/<PID>/root` gives a
		 * root filesystem viewed from the process' perspective, unlike
		 * `/proc/<PID>/maps`, which only gives information about
		 * what the process thinks the paths are. This is useful for
		 * getting modules for apps that are "virtualized", like Flatpaks
		 * and others.
		 * TODO: Test this on BSD.
		 */
		/*
#		if LM_OS == LM_OS_LINUX
		{
			lm_char_t old_path[LM_PATH_MAX];

			LM_STRNCPY(old_path, mod.path, LM_PATH_MAX);
			LM_SNPRINTF(mod.path, LM_ARRLEN(mod.path), LM_STR("/proc/%d/root%s"), pproc->pid, old_path);
		}
#		endif
		*/
		callback(&mod, arg);
	}

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

LM_API lm_bool_t
LM_FindModuleEx(lm_process_t *pproc,
		lm_string_t   name,
		lm_module_t  *modbuf)
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

/*
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

	modpath_size = (LM_STRLEN(path) + 1) * sizeof(lm_char_t);
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
		goto FREE_EXIT;

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
*/

#if LM_OS == LM_OS_BSD
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
#else
#include <injector.h>

LM_PRIVATE lm_bool_t
_LM_LoadModuleEx(lm_process_t *pproc,
		 lm_string_t   path,
		 lm_module_t  *modbuf)
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

LM_API lm_bool_t
LM_LoadModuleEx(lm_process_t *pproc,
		lm_string_t   path,
		lm_module_t  *modbuf)
{
	LM_ASSERT(pproc != LM_NULLPTR && LM_VALID_PROCESS(pproc) && path != LM_NULLPTR);
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

LM_API lm_bool_t
LM_UnloadModule(lm_module_t *pmod)
{
	if (!pmod || !LM_VALID_MODULE(pmod))
		return LM_FALSE;

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
	LM_ASSERT(pproc != LM_NULLPTR &&
		  LM_VALID_PROCESS(pproc) &&
		  pmod != LM_NULLPTR &&
		  LM_VALID_MODULE(pmod));

	return _LM_UnloadModuleEx(pproc, pmod);
}

