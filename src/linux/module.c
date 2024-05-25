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
#include <posixutils/posixutils.h>
#include "consts.h"
#include "ptrace/ptrace.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>

LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					       lm_void_t   *arg),
		 lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	char path[PATH_MAX];
	char module_path[PATH_MAX];
	DIR *map_files;
	struct dirent *dirent;
	unsigned long long base;
	unsigned long long end;
	ssize_t len;
	lm_module_t module;

	if (!process || !callback)
		return result;

	snprintf(path, sizeof(path), "%s/%d/map_files", PROCFS_PATH, process->pid);
	map_files = opendir(path);
	if (!map_files)
		return result;

	module.base = (unsigned long long)LM_ADDRESS_BAD;

	while ((dirent = readdir(map_files))) {
		if (sscanf(dirent->d_name, "%llx-%llx", &base, &end) != 2)
			continue;

		snprintf(path, sizeof(path), "%s/%d/map_files/%s", PROCFS_PATH, process->pid, dirent->d_name);
		if ((len = readlink(path, module_path, sizeof(module_path) - 1)) == -1)
			goto CLOSE_EXIT;
		module_path[len] = '\0';

		/*
		 * NOTE: This is a fix for sandboxed apps like Flatpak
		 *       They can contain "virtual" paths like /app which
		 *       don't actually exist in the filesystem. To access
		 *       those files, we need to read from the directory
		 *       '/proc/<pid>/root/<virtual path>'. This works for
		 *       regular apps as well.
		 */
		snprintf(path, sizeof(path), "%s/%d/root%s", PROCFS_PATH, process->pid, module_path);
		snprintf(module_path, sizeof(module_path), "%s", path);

		if (module.base == LM_ADDRESS_BAD) {
			module.base = (lm_address_t)base;
			module.end = (lm_address_t)end;
			snprintf(module.path, sizeof(module.path), "%s", module_path);
			if (!get_name_from_path(module.path, module.name, sizeof(module.name)))
				goto CLOSE_EXIT;

			continue;
		}

		/* Check if it is the same module, because they are in the same region and have the same path */
		if ((lm_address_t)base == module.end && !strcmp(module_path, module.path)) {
			module.end = end;
		} else {
			module.size = module.end - module.base;
			if (callback(&module, arg) == LM_FALSE) {
				result = LM_TRUE;
				goto CLOSE_EXIT;
				break;
			}

			module.base = (lm_address_t)base;
			module.end = (lm_address_t)end;
			snprintf(module.path, sizeof(module.path), "%s", module_path);
			if (!get_name_from_path(module.path, module.name, sizeof(module.name)))
				goto CLOSE_EXIT;
		}
	}

	/* The callback did not return LM_FALSE yet, and we still have the last module left feed it
	 * (due to the way the algorithm works, the last module is left out, so that's why we need this) */
	if (module.base != LM_ADDRESS_BAD) {
		callback(&module, arg);
	}

	result = LM_TRUE;
CLOSE_EXIT:
	closedir(map_files);
	return result;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_LoadModule(lm_string_t  path,
	      lm_module_t *module_out)
{
	if (!path)
		return LM_FALSE;
	
	if (!dlopen(path, RTLD_LAZY))
		return LM_FALSE;

	if (module_out)
		return LM_FindModule(path, module_out);

	return LM_TRUE;
}

/********************************/

lm_bool_t
find_dlfcn_module_callback(lm_module_t *module, lm_void_t *arg)
{
	static const char *name_matches[] = {
		"libc.", "libc-", "libdl.", "libdl-", "ld-musl-", "ld-musl."
	};
	size_t i;
	size_t len;

	for (i = 0; i < LM_ARRLEN(name_matches); ++i) {
		len = strlen(name_matches[i]);
		if (!strncmp(module->name, name_matches[i], len)) {
			*(lm_module_t *)arg = *module;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

lm_bool_t
find_dlopen_symbol_callback(lm_symbol_t *symbol, lm_void_t *arg)
{
	static const char *symbol_matches[] = {
		"__libc_dlopen_mode", "dlopen"
	};
	size_t i;

	for (i = 0; i < LM_ARRLEN(symbol_matches); ++i) {
		if (!strcmp(symbol->name, symbol_matches[i])) {
			*(lm_address_t *)arg = symbol->address;
			return LM_FALSE;
		}
	}

	return LM_TRUE;
}

LM_API lm_bool_t LM_CALL
LM_LoadModuleEx(const lm_process_t *process,
		lm_string_t         path,
		lm_module_t        *module_out)
{
	lm_bool_t ret = LM_FALSE;
	lm_module_t dlopen_mod;
	lm_address_t dlopen_addr = LM_ADDRESS_BAD;
	size_t path_size;
	lm_address_t path_addr;
	ptrace_libcall_t ptlib;
	long call_ret;

	if (!process || !path)
		return ret;

	dlopen_mod.base = LM_ADDRESS_BAD;
	LM_EnumModulesEx(process, find_dlfcn_module_callback, &dlopen_mod);
	if (dlopen_mod.base == LM_ADDRESS_BAD)
		return ret;

	LM_EnumSymbols(&dlopen_mod, find_dlopen_symbol_callback, &dlopen_addr);
	if (dlopen_addr == LM_ADDRESS_BAD)
		return ret;

	path_size = (strlen(path) + 1) * sizeof(char);
	path_addr = LM_AllocMemoryEx(process, path_size, LM_PROT_RW);
	if (path_addr == LM_ADDRESS_BAD)
		return ret;

	if (LM_WriteMemoryEx(process, path_addr, path, path_size) != path_size)
		goto FREE_EXIT;

	/* Setup arguments both on the stack and on registers to prevent possible issues */
	ptlib.address = dlopen_addr;
	ptlib.args[0] = path_addr;
	ptlib.args[1] = RTLD_LAZY;
	if (process->bits == 64) {
		*(uint64_t *)&ptlib.stack[0] = (uint64_t)path_addr;
		*(int32_t *)&ptlib.stack[8] = (int32_t)RTLD_LAZY;
	} else {
		*(uint32_t *)&ptlib.stack[0] = (uint32_t)path_addr;
		*(int32_t *)&ptlib.stack[4] = (int32_t)RTLD_LAZY;
	}

	if (ptrace_attach(process->pid))
		goto FREE_EXIT;

	call_ret = ptrace_libcall(process->pid, process->bits, &ptlib);
	if (call_ret == -1 || call_ret == 0)
		goto DETACH_EXIT;

	if (module_out)
		ret = LM_FindModuleEx(process, path, module_out);
	else
		ret = LM_TRUE;
DETACH_EXIT:
	ptrace_detach(process->pid);
FREE_EXIT:
	LM_FreeMemoryEx(process, path_addr, path_size);
	return ret;
}

/********************************/

LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module)
{
	void *handle;
	struct link_map *link_map;

	if (!module)
		return LM_FALSE;

	handle = dlopen(NULL, RTLD_LAZY); /* Get process first handle */
	if (!handle)
		return LM_FALSE;

	/*
	 * NOTE: A handle is just 'struct link_map *' internally,
	 *       so we can loop through the link map chain and find
	 *       the module handle
	 * WARN: This may change in the future!
	 */

	for (link_map = (struct link_map *)handle; link_map; link_map = link_map->l_next) {
		/* NOTE: There can be multiple instances of a module loaded in the link_map chain,
		 *       so we can't break the loop until all of them are gone */
		if (link_map->l_addr == module->base) {
			handle = (void *)link_map;

			/*
			 * NOTE: This may not be enough to unload a library
			 * NOTE: dlclose on musl is a no-op as of now
			 */
			dlclose(handle);
			break;

			/*
			 * NOTE: Although not deeply tested, it seems that the link_map chain
			 *       does not delete items that have been dlclosed, so we don't have
			 *       to do anything special to handle the state of the linked list.
			 */
		}
	}

	return LM_TRUE;
}

/********************************/

typedef struct {
	lm_address_t dlopen_addr;
	lm_address_t dlclose_addr;
} find_dlfcn_t;

lm_bool_t
find_dlfcn_symbols_callback(lm_symbol_t *symbol, lm_void_t *arg)
{
	static const char *dlopen_matches[] = {
		"__libc_dlopen_mode", "dlopen"
	};
	static const char *dlclose_matches[] = {
		"__libc_dlclose", "dlclose"
	};
	find_dlfcn_t *parg = (find_dlfcn_t *)arg;
	size_t i;

	for (i = 0; i < LM_ARRLEN(dlopen_matches); ++i) {
		if (!strcmp(symbol->name, dlopen_matches[i])) {
			parg->dlopen_addr = symbol->address;
		}
	}

	for (i = 0; i < LM_ARRLEN(dlclose_matches); ++i) {
		if (!strcmp(symbol->name, dlclose_matches[i])) {
			parg->dlclose_addr = symbol->address;
		}
	}

	return (parg->dlopen_addr == LM_ADDRESS_BAD || parg->dlclose_addr == LM_ADDRESS_BAD) ? LM_TRUE : LM_FALSE;
}

LM_API lm_bool_t LM_CALL
LM_UnloadModuleEx(const lm_process_t *process,
		  const lm_module_t  *module)
{
	lm_bool_t ret = LM_FALSE;
	lm_module_t dlfcn_mod;
	find_dlfcn_t dlfcn = { LM_ADDRESS_BAD, LM_ADDRESS_BAD };
	ptrace_libcall_t ptlib;
	long link_map_iter;
	struct link_map link_map;
	void *handle = NULL;
	long call_ret;

	if (!process || !module)
		return ret;

	dlfcn_mod.base = LM_ADDRESS_BAD;
	LM_EnumModulesEx(process, find_dlfcn_module_callback, &dlfcn_mod);
	if (dlfcn_mod.base == LM_ADDRESS_BAD)
		return ret;

	LM_EnumSymbols(&dlfcn_mod, find_dlfcn_symbols_callback, &dlfcn);
	if (dlfcn.dlopen_addr == LM_ADDRESS_BAD || dlfcn.dlclose_addr == LM_ADDRESS_BAD)
		return ret;

	/* Setup arguments both on the stack and on registers to prevent possible issues */
	ptlib.address = dlfcn.dlopen_addr;
	ptlib.args[0] = (long)NULL;
	ptlib.args[1] = RTLD_LAZY;
	if (process->bits == 64) {
		*(uint64_t *)&ptlib.stack[0] = (uint64_t)NULL;
		*(int32_t *)&ptlib.stack[8] = (int32_t)RTLD_LAZY;
	} else {
		*(uint32_t *)&ptlib.stack[0] = (uint32_t)LM_NULL;
		*(int32_t *)&ptlib.stack[4] = (int32_t)RTLD_LAZY;
	}

	if (ptrace_attach(process->pid))
		goto EXIT;

	link_map_iter = ptrace_libcall(process->pid, process->bits, &ptlib);
	if (link_map_iter == -1 || link_map_iter == 0)
		goto DETACH_EXIT;

	/* Search for the correct handle, just like in LM_UnloadModule */
	for (; link_map_iter; link_map_iter = (long)link_map.l_next) {
		if (ptrace_read(process->pid, link_map_iter, (char *)&link_map, sizeof(link_map)) != sizeof(link_map))
			goto DETACH_EXIT;

		if (link_map.l_addr == module->base) {
			handle = (void *)link_map_iter;
			break;
		}
	}

	if (!handle) {
		/* If no handle was found, it means that the module is already unloaded */
		ret = LM_TRUE;
		goto DETACH_EXIT;
	}

	/* Call dlclose with the handle we found */
	ptlib.address = dlfcn.dlclose_addr;
	ptlib.args[0] = (long)handle;
	if (process->bits == 64) {
		*(uint64_t *)&ptlib.stack[0] = (uint64_t)handle;
	} else {
		*(uint32_t *)&ptlib.stack[0] = (uint32_t)(uint64_t)handle;
	}

	call_ret = ptrace_libcall(process->pid, process->bits, &ptlib);
	if (call_ret != 0)
		goto DETACH_EXIT;

	ret = LM_TRUE;
DETACH_EXIT:
	ptrace_detach(process->pid);
EXIT:
	return ret;
}
