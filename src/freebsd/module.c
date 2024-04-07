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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <libprocstat.h>
#include <dlfcn.h>

LM_API lm_bool_t LM_CALL
LM_EnumModulesEx(const lm_process_t *process,
		 lm_bool_t (LM_CALL *callback)(lm_module_t *module,
					       lm_void_t   *arg),
		 lm_void_t          *arg)
{
	lm_bool_t result = LM_FALSE;
	struct procstat *ps;
	struct kinfo_proc *proc;
	struct kinfo_vmentry *vmmap;
	unsigned int count;
	unsigned int i;
	unsigned int j;
	lm_module_t module;
	
	if (!process || !callback)
		return result;

	ps = procstat_open_sysctl();
	if (!ps)
		return result;

	proc = procstat_getprocs(ps, KERN_PROC_PID, process->pid, &count);
	if (!proc)
		goto CLOSE_EXIT;

	vmmap = procstat_getvmmap(ps, proc, &count);
	procstat_freeprocs(ps, proc);
	if (!vmmap)
		goto CLOSE_EXIT;

	for (i = 0; i < count;) {
		if (strlen(vmmap[i].kve_path) == 0) {
			++i;
			continue;
		}

		module.base = (lm_address_t)vmmap[i].kve_start;
		module.end = (lm_address_t)vmmap[i].kve_end;
		snprintf(module.path, sizeof(module.path), "%s", vmmap[i].kve_path);

		/* Get maximum sequential address range for a module
		 * (similar to how the linux version of this API is done) */
		for (j = i + 1; j < count && (lm_address_t)vmmap[j].kve_start == module.end && !strcmp(vmmap[j].kve_path, module.path); ++j) {
			module.end = (lm_address_t)vmmap[j].kve_end;
		}

		module.size = module.end - module.base;
		get_name_from_path(module.path, module.name, sizeof(module.name));

		if (callback(&module, arg) == LM_FALSE)
			break;

		/* Skip to next module */
		i = j;
	}

	result = LM_TRUE;

	procstat_freevmmap(ps, vmmap);
CLOSE_EXIT:
	procstat_close(ps);
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

	if (!module)
		return LM_FALSE;

	handle = dlopen(module->path, RTLD_NOLOAD); /* Increases the reference count by 1 */
	if (!handle)
		return LM_FALSE;

	/* Decrease the reference count and possibly force the module to unload */
	/* NOTE: It is not guaranteed that the module will unload after this! */
	dlclose(handle);
	dlclose(handle);

	return LM_TRUE;
}
