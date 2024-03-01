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
		return LM_FALSE;

	snprintf(path, sizeof(path), "%s/%d/map_files", PROCFS_PATH, process->pid);
	map_files = opendir(path);
	if (!map_files)
		return LM_FALSE;

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
	return LM_TRUE;
}
