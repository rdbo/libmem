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

LM_API lm_bool_t LM_CALL
LM_UnloadModule(const lm_module_t *module)
{
	void *handle;
	struct link_map *link_map;
	size_t modpath_len;
	size_t len;

	if (!module)
		return LM_FALSE;

	handle = dlopen(NULL, 0); /* Get process first handle */
	if (!handle)
		return LM_FALSE;

	modpath_len = strlen(module->path);

	/*
	 * NOTE: A handle is just 'struct link_map *' internally,
	 *       so we can loop through the link map chain and find
	 *       the module handle
	 * WARN: This may change in the future!
	 */

	for (link_map = (struct link_map *)handle; link_map; link_map = link_map->l_next) {
		len = strlen(link_map->l_name);
		if (len > modpath_len)
			continue;

		/* NOTE: There can be multiple instances of a module loaded in the link_map chain,
		 *       so we can't break the loop until all of them are gone */
		if (!strcmp(&module->path[modpath_len - len], link_map->l_name)) {
			handle = (void *)link_map;

			/*
			 * NOTE: This may not be enough to unload a library
			 * NOTE: dlclose on musl is a no-op as of now
			 */
			dlclose(handle);

			/*
			 * NOTE: Although not deeply tested, it seems that the link_map chain
			 *       does not delete items that have been dlclosed, so we don't have
			 *       to do anything special to handle the state of the linked list.
			 */
		}
	}

	return LM_TRUE;
}
